# C++ Defense Evasion Loader

A custom lightweight loader implemented in C++ designed to demonstrate endpoint security control evasion techniques. This project is built strictly for educational purposes, cyber defense testing, and practicing on gamified labs such as HackTheBox and Vulnlab.

## Features
* **Mitigation Policies:** Restricts non-Microsoft binary loading (`BlockDlls`) to prevent third-party security vendors from hooking the process.
* **Syscalls:** Integrates custom syscalls to bypass User-Mode API hooking on critical memory and execution functions.
* **Lab-Friendly:** Optimized for testing signature and heuristic-based detection mechanisms in controlled environments.

## Core Architecture & Syscalls

To minimize the reliance on monitored Win32 APIs, this loader utilizes indirect system calls generated via **SysWhispers3** (using the `jumper` method). 

The following native APIs are leveraged for memory manipulation and execution flow control:
* `NtWriteVirtualMemory`
* `NtProtectVirtualMemory`
* `NtQueueApcThread`
* `NtResumeThread`

### SysWhispers3 Generation Usage

To reproduce or update the syscall stubs used in this project:

```bash
# Clone the SysWhispers3 repository
git clone https://github.com/klezVirus/SysWhispers3

# Generate the syscall files
python syswhispers.py --functions NtWriteVirtualMemory,NtProtectVirtualMemory,NtQueueApcThread,NtResumeThread --arch x64 --compiler msvc --method jumper -o syscalls
```
- How to Integrate SysWhispers3 Files into Visual Studio

Once you have generated your `syscalls.h`, `syscalls.c`, and `syscalls.asm` files, follow these steps to integrate them into your Visual Studio C++ project:

*Copy the Files*
Copy the generated **`.h`**, **`.c`**, and **`.asm`** files directly into your project directory.

*Enable MASM Support*
Before adding the files to the solution, you must tell Visual Studio to support Assembly compilation:
1. In the top menu, go to **Project** → **Build Customizations...**
2. Check the box next to **masm** (`.targets`, `.props`).
3. Click **OK**.

*Add Files to the Project*
In the **Solution Explorer** on the right side:
* Right-click **Header Files** → **Add** → **Existing Item...** → Select `syscalls.h`.
* Right-click **Source Files** → **Add** → **Existing Item...** → Select `syscalls.c` and `syscalls.asm`.

*Configure the ASM File Properties*
Windows requires the assembly file to be compiled using the proper assembler tool:
1. Right-click on `syscalls.asm` in the **Solution Explorer** and select **Properties**.
2. Set the **Configuration** dropdown at the top to **All Configurations**.
3. Under **General**, locate the **Item Type** field.
4. Change it from *Does not participate in build* to **Microsoft Macro Assembler**.
5. Click **Apply** and **OK**.


## payload_encryptor.py usage

You can use the provided Python script to encrypt your raw shellcode/payload using AES-128 CBC mode with automatic PKCS7 padding. 

- Commands

```bash
# Install dependencies (if not already installed)
pip3 install pycryptodome

# Run the encryptor script against your raw binary file
python3 payload_encryptor.py api.bin

```

- Expected Output Example
When running the script, it will generate `<filename>.enc` and `<filename>.key` files in your current working directory and output a clean summary containing the hex keys to paste into your loader:

```
[*] Shellcode loaded: 10035932 bytes
[+] Encrypted shellcode written to: api.enc
[+] Key and IV saved to: api.key

============================================================
SUMMARY - INTEGRATE INTO YOUR LOADER:
============================================================
Encrypted File   : api.enc
Original Size    : 10035932 bytes
Encrypted Size   : 10035936 bytes
Key Size         : 16 bytes (AES-128)
IV Size          : 16 bytes

Key (hex) : 8b343324f73b9e3bb5b2313a4b673b5b
IV  (hex) : 1f692c214a52a0cd1795f0978f322a78
```

The generated `.key` file will also contain pre-formatted `C/C++`, `Rust`, and `Python` byte arrays for convenience.


## Disclaimer

This tool is developed strictly for educational purposes, authorized security research, and personal skill development. It is designed to assist users in understanding defense evasion concepts within controlled environments, such as HackTheBox and Vulnlab platforms.

The author assumes no liability or responsibility for any misuse, damage, or illegal activities conducted with this software. Using this tool against production systems or without explicit, written authorization from the infrastructure owner is strictly prohibited. By using this software, you agree to comply with all applicable local and international laws.
