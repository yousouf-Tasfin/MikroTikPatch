import subprocess, os, re
import struct
import lzma
from npk import NovaPackage, NpkPartID, NpkFileContainer

# --- Helper Functions ---
def run_shell_command(command):
    """Run shell command with error handling"""
    try:
        process = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        return process.stdout, process.stderr
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {command}")
        print(f"Error: {e.stderr}")
        raise

# --- Key Replacement Logic ---
def replace_key(old_key, new_key, data, name=""):
    """Replace old_key with new_key in data"""
    if old_key in data:
        print(f"{name} public key patched {old_key[:16].hex().upper()}...")
        return data.replace(old_key, new_key)
    return data

def patch_kernel(data, key_dict):
    """Patch kernel with custom keys"""
    if data[:2] == b'MZ':
        print('Patching EFI Kernel')
        return patch_bzimage(data, key_dict)
    elif data[:4] == b'\x7FELF':
        print('Patching ELF')
        return patch_elf(data, key_dict)
    elif data[:5] == b'\xFD7zXZ':
        print('Patching initrd')
        return patch_initrd_xz(data, key_dict)
    else:
        raise Exception('Unknown kernel format')

# --- Bootloader Patching ---
def patch_bzimage(data, key_dict):
    """Patch bzImage with custom keys"""
    PE_TEXT_SECTION_OFFSET = 414
    HEADER_PAYLOAD_OFFSET = 584
    HEADER_PAYLOAD_LENGTH_OFFSET = HEADER_PAYLOAD_OFFSET + 4

    text_section_raw_data = struct.unpack_from('<I', data, PE_TEXT_SECTION_OFFSET)[0]
    payload_offset = text_section_raw_data + struct.unpack_from('<I', data, HEADER_PAYLOAD_OFFSET)[0]
    payload_length = struct.unpack_from('<I', data, HEADER_PAYLOAD_LENGTH_OFFSET)[0]
    payload_length -= 4  # Last 4 bytes = uncompressed size
    z_output_len = struct.unpack_from('<I', data, payload_offset + payload_length)[0]
    vmlinux_xz = data[payload_offset:payload_offset + payload_length]

    try:
        vmlinux = lzma.decompress(vmlinux_xz)
    except Exception as e:
        raise Exception(f"Failed to decompress vmlinux.xz: {e}")

    # Patch initramfs inside vmlinux
    CPIO_HEADER_MAGIC = b'07070100'
    CPIO_FOOTER_MAGIC = b'TRAILER!!!\x00\x00\x00\x00'

    cpio_offset1 = vmlinux.find(CPIO_HEADER_MAGIC)
    if cpio_offset1 == -1:
        raise Exception("CPIO header not found in vmlinux")

    initramfs = vmlinux[cpio_offset1:]
    cpio_offset2 = initramfs.find(CPIO_FOOTER_MAGIC) + len(CPIO_FOOTER_MAGIC)
    initramfs = initramfs[:cpio_offset2]

    # Apply key replacements
    new_initramfs = initramfs
    for old_key, new_key in key_dict.items():
        new_initramfs = replace_key(old_key, new_key, new_initramfs, "initramfs")

    # Recompress vmlinux
    new_vmlinux = vmlinux.replace(initramfs, new_initramfs)
    new_vmlinux_xz = lzma.compress(new_vmlinux, check=lzma.CHECK_CRC32, filters=[
        {"id": lzma.FILTER_X86},
        {"id": lzma.FILTER_LZMA2, "preset": 9 | lzma.PRESET_EXTREME,
         "dict_size": 32 * 1024 * 1024, "lc": 4, "lp": 0, "pb": 0}
    ])

    # Ensure new size doesn't exceed original
    if len(new_vmlinux_xz) + 4 > payload_length:
        raise Exception("New vmlinux.xz too large")

    # Update payload length and data
    new_payload_length = len(new_vmlinux_xz) + 4
    new_data = bytearray(data)
    struct.pack_into('<I', new_data, HEADER_PAYLOAD_LENGTH_OFFSET, new_payload_length)
    vmlinux_xz += struct.pack('<I', z_output_len)
    new_vmlinux_xz += struct.pack('<I', z_output_len)
    new_vmlinux_xz = new_vmlinux_xz.ljust(len(vmlinux_xz), b'\0')
    return bytes(new_data.replace(vmlinux_xz, new_vmlinux_xz))

def patch_elf(data, key_dict):
    """Patch ELF kernel"""
    return patch_initrd_xz(find_7zXZ_data(data), key_dict)

def find_7zXZ_data(data):
    """Find 7zXZ compressed data in binary"""
    start = data.find(b'\xFD7zXZ\x00\x00\x01')
    if start == -1:
        raise Exception("7zXZ header not found")
    end = data.find(b'\x00\x00\x00\x00\x01\x59\x5A', start)
    if end == -1:
        raise Exception("7zXZ footer not found")
    return data[start:end + 7]

def patch_initrd_xz(initrd_xz, key_dict, ljust=True):
    """Patch initrd.xz with custom keys"""
    try:
        initrd = lzma.decompress(initrd_xz)
    except Exception as e:
        raise Exception(f"Failed to decompress initrd.xz: {e}")

    # Apply key replacements
    new_initrd = initrd
    for old_key, new_key in key_dict.items():
        new_initrd = replace_key(old_key, new_key, new_initrd, "initrd")

    # Recompress with maximum compression
    new_initrd_xz = lzma.compress(new_initrd, check=lzma.CHECK_CRC32, filters=[
        {"id": lzma.FILTER_LZMA2, "preset": 9 | lzma.PRESET_EXTREME,
         "dict_size": 32 * 1024 * 1024, "lc": 4, "lp": 0, "pb": 0}
    ])

    if ljust and len(new_initrd_xz) < len(initrd_xz):
        new_initrd_xz = new_initrd_xz.ljust(len(initrd_xz), b'\0')
    return new_initrd_xz

# --- NPK File Handling ---
def patch_npk_package(package, key_dict):
    """Patch NPK package with custom keys"""
    if package[NpkPartID.NAME_INFO].data.name == b'system':
        file_container = NpkFileContainer.unserialize_from(package[NpkPartID.FILE_CONTAINER].data)
        
        # Patch kernel/initrd
        for item in file_container:
            if item.name in [b'boot/kernel', b'boot/initrd.rgz']:
                print(f"Patching {item.name}...")
                item.data = patch_kernel(item.data, key_dict)
        
        package[NpkPartID.FILE_CONTAINER].data = file_container.serialize()

        # Patch squashfs
        squashfs_file = 'squashfs-root.sfs'
        extract_dir = 'squashfs-root'
        sfs_data = package[NpkPartID.SQUASHFS].data
        open(squashfs_file, 'wb').write(sfs_data)

        print(f"Extracting {squashfs_file}...")
        run_shell_command(f"unsquashfs -d {extract_dir} {squashfs_file}")

        # Apply key replacements inside squashfs
        patch_squashfs(extract_dir, key_dict)

        print(f"Packing {extract_dir}...")
        run_shell_command(f"mksquashfs {extract_dir} {squashfs_file} -quiet -comp xz -no-xattrs -b 256k")

        print("Cleaning up...")
        package[NpkPartID.SQUASHFS].data = open(squashfs_file, 'rb').read()
        os.remove(squashfs_file)
        os.system(f"rm -rf {extract_dir}")

def patch_npk_file(key_dict, kcdsa_private_key, eddsa_private_key, input_file, output_file=None):
    """Patch and resign NPK file"""
    npk = NovaPackage.load(input_file)
    
    if len(npk._packages) > 0:
        for package in npk._packages:
            patch_npk_package(package, key_dict)
    else:
        patch_npk_package(npk, key_dict)
    
    npk.sign(kcdsa_private_key, eddsa_private_key)
    npk.save(output_file or input_file)

# --- Main Entry Point ---
if __name__ == '__main__':
    import argparse, os
    parser = argparse.ArgumentParser(description='MikroTik NPK Patcher')
    subparsers = parser.add_subparsers(dest="command")

    # NPK Command
    npk_parser = subparsers.add_parser('npk', help='Patch and sign NPK file')
    npk_parser.add_argument('input', type=str, help='Input file')
    npk_parser.add_argument('-O', '--output', type=str, help='Output file')

    # Kernel Command
    kernel_parser = subparsers.add_parser('kernel', help='Patch kernel file')
    kernel_parser.add_argument('input', type=str, help='Input file')
    kernel_parser.add_argument('-O', '--output', type=str, help='Output file')

    args = parser.parse_args()

    # Load keys from environment
    key_dict = {
        bytes.fromhex(os.environ['MIKRO_LICENSE_PUBLIC_KEY']): bytes.fromhex(os.environ['CUSTOM_LICENSE_PUBLIC_KEY']),
        bytes.fromhex(os.environ['MIKRO_NPK_SIGN_PUBLIC_KEY']): bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PUBLIC_KEY'])
    }
    kcdsa_private_key = bytes.fromhex(os.environ['CUSTOM_LICENSE_PRIVATE_KEY'])
    eddsa_private_key = bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PRIVATE_KEY'])

    # Execute command
    if args.command == 'npk':
        print(f"Patching {args.input}...")
        patch_npk_file(key_dict, kcdsa_private_key, eddsa_private_key, args.input, args.output)
    elif args.command == 'kernel':
        print(f"Patching {args.input}...")
        data = open(args.input, 'rb').read()
        patched_data = patch_kernel(data, key_dict)
        open(args.output or args.input, 'wb').write(patched_data)
    else:
        parser.print_help()
