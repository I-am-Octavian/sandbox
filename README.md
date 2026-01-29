# eBPF Handler with Policy Configuration

This project demonstrates an eBPF-based handler that reads configuration from a JSON policy file. It's built on top of the [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) framework.

## Contents

This package includes:
- `handler.h` - Header file for the handler
- `handler.c` - Main handler implementation
- `handler.bpf.c` - eBPF program
- `policy.json` - Policy configuration file
- `setup_and_run_handler.sh` - Setup and execution script

## Prerequisites

- **Sudo Access Required**: This project requires root privileges to load and run eBPF programs
- **Linux Kernel**: Kernel version 5.8 or higher recommended(This project was tested to work only on Debian 13. Although the code is expected, but not guaranteed to run on other operating systems, due to kernel changes from version to version)
- **Dependencies**: 
  - `clang` - Compiler for eBPF programs
  - `libelf1` and `libelf-dev` - ELF library
  - `zlib1g-dev` - Compression library
  - `llvm` - LLVM compiler infrastructure
  - `libjson-c-dev` - JSON-C library for parsing policy.json
  - `git` - For cloning the libbpf-bootstrap repository
  - `make` - Build system
  - `gcc` - GNU C compiler

The setup script will attempt to install these dependencies automatically.

## Quick Start

1. **Make the script executable:**
   ```bash
   chmod +x setup_and_run_handler.sh
   ```

2. **Run the script:**
   ```bash
   ./setup_and_run_handler.sh
   ```

That's it! The script will:
- Check and install required dependencies
- Clone the libbpf-bootstrap repository
- Copy all necessary files
- Modify the Makefile to include the handler
- Build the handler program
- Run the handler with the policy.json configuration

## What the Script Does

The setup script automates the entire build and execution process:

1. **Dependency Check**: Installs required packages if not already present
2. **Repository Setup**: Clones the libbpf-bootstrap framework
3. **File Deployment**: Copies handler files and policy configuration
4. **Build Configuration**: Updates the Makefile to:
   - Add `handler` to the build targets
   - Link against `libjson-c` library
5. **Compilation**: Builds the handler using `make handler`
6. **Execution**: Runs the handler with sudo privileges using the policy.json file

## Manual Installation (Optional)

If you prefer to install dependencies manually:

### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install -y clang libelf1 libelf-dev zlib1g-dev llvm libjson-c-dev git make gcc libcjson-dev
```

### Fedora/RHEL:
```bash
sudo dnf install -y clang elfutils-libelf elfutils-libelf-devel zlib-devel llvm json-c-devel git make gcc
```

### Arch Linux:
```bash
sudo pacman -S clang libelf zlib llvm json-c git make gcc
```

## Troubleshooting

### Permission Denied
If you get a "Permission denied" error, ensure the script is executable:
```bash
chmod +x setup_and_run_handler.sh
```

### Sudo Password
The script will prompt for your sudo password when:
- Installing dependencies
- Running the eBPF handler (requires root privileges)

### Build Errors
If the build fails:
1. Ensure all dependencies are installed
2. Check that your kernel headers are installed: `sudo apt install linux-headers-$(uname -r)`
3. Verify your kernel version: `uname -r` (should be 5.8+)

### eBPF Loading Issues
If the handler fails to load eBPF programs:
- Ensure you have sufficient privileges (running with sudo)
- Check kernel BPF support: `zgrep CONFIG_BPF /proc/config.gz`
- Review kernel logs: `sudo dmesg | tail`

## Customization

### Modifying the Policy
Edit `policy.json` to customize the handler's behavior before running the script. The setup script automatically runs the sandbox for you. If you wish to run the code again after stopping the sandbox once run :

```bash
sudo ./handler policy.json
```
This binary should be built by the setup file and will be located in the `libbpf-bootstrap/examples/c/` directory.

However, modifying the policy does not require the code to be run again. The program suport policy "Hot-Reload". Just modify `policy.json` file while the code is running. When you save the policy file, it is automatically reloaded live. No need to stop and rerun the program to apply changes in to the polices.

PS: The policy also supports `*`(Wildcard) operation for allowed_domains, filesystem_policies and security_policies. An example is shown below:

```
{
    "policy_version": "1.0" ,
    "command": "cat",
    "filesystem_policies": {
        "allowed_write_dirs": ["*"],
        "blocked_read_dirs": []
        },
    "security_policies": {
        "blocked_environment": ["PASSWORD"]
        }
}
```

This policy allows all domains and all directories are writeable.

Note:
1. blocked_environment wildcard is restrictive wildcard. Placing wildcard there will block access to all environemt varibles for that "command".
2. command does not support wildcard. This is to prevent accidental wildcard placement on both command and blocked_environment, which is potentially a breaking policy, which could brick the kernel, blocking environment access for all programs.

## Cleanup

To remove the cloned repository and start fresh:
```bash
rm -rf libbpf-bootstrap
```

Then run the setup script again.

## Project Structure

After running the script, the directory structure will be:
```
.
├── handler.h
├── handler.c
├── handler.bpf.c
├── policy.json
├── setup_and_run_handler.sh
└── libbpf-bootstrap/          (created by script)
    └── examples/c/
        ├── handler.h          (copied)
        ├── handler.c          (copied)
        ├── handler.bpf.c      (copied)
        ├── policy.json        (copied)
        ├── handler            (compiled binary)
        └── Makefile           (modified)
```

## License

This project builds upon [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap), which is licensed under BSD-3-Clause and GPL-2.0.
