import struct
import lzma
import os
from npk import NovaPackage, NpkPartID, NpkFileContainer

def replace_key(old_key, new_key, data, name=""):
    """Replace old_key with new_key in data"""
    if old_key in data:
        print(f"{name} public key patched {old_key[:16].hex().upper()}...")
        return data.replace(old_key, new_key)
    return data

def patch_kernel(data, key_dict):
    """Basic x86 kernel patching"""
    if data[:2] == b'MZ':  # x86 EFI kernel
        print('Patching x86 kernel')
        return patch_bzimage(data, key_dict)
    elif data[:5] == b'\xFD7zXZ':  # x86 initrd
        print('Patching x86 initrd')
        return patch_initrd_xz(data, key_dict)
    return data

def patch_bzimage(data, key_dict):
    """Minimal x86 bzImage patching"""
    try:
        # Find payload offset
        PE_TEXT_SECTION_OFFSET = 414
        HEADER_PAYLOAD_OFFSET = 584
        HEADER_PAYLOAD_LENGTH_OFFSET = HEADER_PAYLOAD_OFFSET + 4
        
        text_section_raw_data = struct.unpack_from('<I', data, PE_TEXT_SECTION_OFFSET)[0]
        payload_offset = text_section_raw_data + struct.unpack_from('<I', data, HEADER_PAYLOAD_OFFSET)[0]
        payload_length = struct.unpack_from('<I', data, HEADER_PAYLOAD_LENGTH_OFFSET)[0]
        payload_length -= 4  # Last 4 bytes = size
        
        vmlinux_xz = data[payload_offset:payload_offset + payload_length]
        vmlinux = lzma.decompress(vmlinux_xz)
        
        # Apply key replacements
        new_vmlinux = vmlinux
        for old_key, new_key in key_dict.items():
            new_vmlinux = replace_key(old_key, new_key, new_vmlinux, "vmlinux")
        
        # Recompress
        new_vmlinux_xz = lzma.compress(new_vmlinux, check=lzma.CHECK_CRC32)
        new_vmlinux_xz += struct.pack('<I', len(new_vmlinux))
        
        # Ensure size doesn't exceed original
        if len(new_vmlinux_xz) > len(vmlinux_xz):
            raise Exception("Patched kernel too large")
            
        return data.replace(vmlinux_xz, new_vmlinux_xz)
        
    except Exception as e:
        print(f"Kernel patch failed: {e}")
        return data

def patch_initrd_xz(initrd_xz, key_dict):
    """Patch initrd.xz with key replacements"""
    try:
        initrd = lzma.decompress(initrd_xz)
        new_initrd = initrd
        for old_key, new_key in key_dict.items():
            new_initrd = replace_key(old_key, new_key, new_initrd, "initrd")
        
        # Recompress with minimal settings
        return lzma.compress(new_initrd, check=lzma.CHECK_CRC32)
        
    except Exception as e:
        print(f"Initrd patch failed: {e}")
        return initrd_xz

def patch_npk_file(key_dict, kcdsa_private_key, eddsa_private_key, input_file, output_file=None):
    """Patch and resign NPK file"""
    npk = NovaPackage.load(input_file)
    
    # Patch all packages
    packages = npk._packages if len(npk._packages) > 0 else [npk]
    
    for package in packages:
        if package[NpkPartID.NAME_INFO].data.name == 'system':
            file_container = NpkFileContainer.unserialize_from(package[NpkPartID.FILE_CONTAINER].data)
            
            # Patch kernel/initrd
            for item in file_container:
                if item.name in [b'boot/kernel', b'boot/initrd.rgz']:
                    print(f"Patching {item.name}...")
                    item.data = patch_kernel(item.data, key_dict)
            
            package[NpkPartID.FILE_CONTAINER].data = file_container.serialize()
    
    # Resign with custom keys
    npk.sign(kcdsa_private_key, eddsa_private_key)
    npk.save(output_file or input_file)

if __name__ == '__main__':
    import argparse, os
    
    parser = argparse.ArgumentParser(description='MikroTik NPK Patcher (x86)')
    subparsers = parser.add_subparsers(dest="command")
    
    # NPK Command
    npk_parser = subparsers.add_parser('npk', help='Patch and sign NPK file')
    npk_parser.add_argument('input', type=str, help='Input NPK file')
    npk_parser.add_argument('-O', '--output', type=str, help='Output file')
    
    args = parser.parse_args()
    
    if args.command != 'npk':
        parser.print_help()
        exit(1)
    
    # Load keys from environment
    key_dict = {
        bytes.fromhex(os.environ['MIKRO_LICENSE_PUBLIC_KEY']): bytes.fromhex(os.environ['CUSTOM_LICENSE_PUBLIC_KEY']),
        bytes.fromhex(os.environ['MIKRO_NPK_SIGN_PUBLIC_KEY']): bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PUBLIC_KEY'])
    }
    kcdsa_private_key = bytes.fromhex(os.environ['CUSTOM_LICENSE_PRIVATE_KEY'])
    eddsa_private_key = bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PRIVATE_KEY'])

    print(f"Patching {args.input}...")
    patch_npk_file(key_dict, kcdsa_private_key, eddsa_private_key, args.input, args.output)
