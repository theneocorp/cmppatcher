# cmppatcher

A one-shot Linux installer that permanently patches NVIDIA mining and compute GPU drivers for all CMP series cards and legacy Pascal mining GPUs. It restores 3D acceleration, bypasses the hardware FP32 FMA throttle on the CMP 170HX, and unlocks NVENC/NVDEC stream limits.

After running `sudo bash install.sh` once, every CUDA and OpenGL/Vulkan application on the system works at full software-recoverable performance with no per-app configuration. The patches automatically reapply whenever the NVIDIA driver package is updated.

## Features

1. **3D Acceleration Unlock (All Supported Cards)**
   NVIDIA disables 3D acceleration (OpenGL/Vulkan) on mining GPUs by excluding their PCI device IDs from driver whitelists. `cmppatcher` binary-patches `libcuda.so`, `libnvidia-glcore.so`, `libGLX_nvidia.so`, and the `nvidia.ko` kernel module to accept these GPUs.
2. **FP32 FMA Throttle Bypass (CMP 170HX Only)**
   The CMP 170HX has hardware-fused silicon that throttles FFMA instructions by 16:1. `cmppatcher` installs a persistent SASS-level rewriting daemon that transparently replaces `FFMA` instructions with an unthrottled `FMUL+FADD` pair at CUDA module load time.
3. **NVENC/NVDEC Session Unlock (All Supported Cards)**
   Removes the artificial cap on concurrent video encode/decode sessions in `libnvidia-encode.so` and `libnvidia-fbc.so`.
4. **Persistent Across Updates**
   Automatically sets up package manager hooks (`apt`, `dnf`, `pacman`) to repatch the driver automatically when you update your system.

## Supported Hardware

**Ampere CMP series**
* CMP 170HX (GA100-105F, ID 0x2081) — *FMA throttle bypass & 3D unlock*
* CMP 90HX, 70HX, 50HX, 40HX, 30HX and variants (0x1F0B, 0x1EFC, 0x1EBC, 0x1E49, 0x1E09, 0x2082, 0x2083, 0x2089, 0x20C2, 0x20C3, 0x220D, 0x224D, 0x248A, 0x248D) — *3D unlock*

**Pascal mining series**
* P102-100 (0x1B07), P104-100 (0x1B87), P106-100 (0x1BC7), P106-090 (0x1C07), P104-101 (0x1C09) — *3D unlock*

## Installation

**Prerequisite:** Ensure **Secure Boot is Disabled** in your motherboard's UEFI/BIOS settings. The patches modify the `nvidia.ko` kernel module, and Linux will refuse to load it if kernel module signature enforcement is active.

```bash
# Clone the repository
git clone https://github.com/amoghmunikote/cmppatcher.git
cd cmppatcher

# Run a dry-run to preview what will be done (optional)
sudo bash install.sh --dry-run

# Run the installer
sudo bash install.sh
```

### Options
* `--dry-run` : Preview patches without modifying any files.
* `--status` : Check the current driver version and patch status.
* `--restore` : Revert all modified driver files to their original state and disable the daemon.
* `--uninstall` : Completely remove `cmppatcher`, all hooks, daemons, and restore original driver files.