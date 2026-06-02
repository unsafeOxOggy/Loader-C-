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
git clone [https://github.com/klezVirus/SysWhispers3](https://github.com/klezVirus/SysWhispers3)

# Generate the syscall files
python syswhispers.py --functions NtWriteVirtualMemory,NtProtectVirtualMemory,NtQueueApcThread,NtResumeThread --arch x64 --compiler msvc --method jumper -o syscalls
```
## Disclaimer

This tool is developed strictly for educational purposes, authorized security research, and personal skill development. It is designed to assist users in understanding defense evasion concepts within controlled environments, such as HackTheBox and Vulnlab platforms.

The author assumes no liability or responsibility for any misuse, damage, or illegal activities conducted with this software. Using this tool against production systems or without explicit, written authorization from the infrastructure owner is strictly prohibited. By using this software, you agree to comply with all applicable local and international laws.
