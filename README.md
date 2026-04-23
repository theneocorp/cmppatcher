# cmppatcher

A one-shot Linux installer that patches NVIDIA mining and compute GPU drivers to restore functionality on CMP series and legacy Pascal mining GPUs.

After running `sudo bash install.sh` once, all CUDA, OpenGL, and Vulkan applications operate at full recoverable performance with no per-application configuration required. Patches are automatically re-applied whenever the NVIDIA driver is updated.

---

## Overview

`cmppatcher` removes artificial limitations imposed on mining GPUs by modifying both user-space libraries and kernel components. It enables full 3D acceleration, unlocks video encoding capabilities where available, and restores compute performance on supported hardware.

---

## Features

### 1. 3D Acceleration Unlock (All Supported GPUs)
Mining GPUs ship with OpenGL and Vulkan disabled via driver-level PCI device ID restrictions.

`cmppatcher` patches:
- `libcuda.so`
- `libnvidia-glcore.so`
- `libGLX_nvidia.so`
- `nvidia.ko` (kernel module)

These modifications allow the driver to recognize and fully enable 3D acceleration on supported GPUs.

---

### 2. FP32 FMA Throttle Bypass (CMP 170HX Only)
The CMP 170HX includes a hardware-level limitation that reduces FFMA instruction throughput by a factor of 16.

`cmppatcher` installs a persistent SASS-level rewriting daemon that:
- Intercepts CUDA module loads
- Replaces `FFMA` instructions with equivalent `FMUL + FADD` sequences
- Restores practical FP32 compute throughput without requiring application changes

---

### 3. NVENC & NvFBC Unlock
Removes software-imposed limits on NVENC encoding sessions and enables NvFBC support.

- Dynamically fetches patch patterns from the official repository:
  https://github.com/keylase/nvidia-patch
- Automatically skips NVENC patching on CMP 170HX (GA100 has no NVENC hardware)

---

### 4. Persistent Across Driver Updates
Integrates with system package managers to automatically reapply patches after driver updates.

Supported package managers:
- `apt`
- `dnf`
- `pacman`

---

## Supported Hardware

### Ampere CMP Series
| GPU | PCI ID | Features |
|-----|--------|---------|
| CMP 170HX | 0x2081 | 3D unlock + FMA bypass |
| CMP 90HX | 0x1F0B | 3D unlock |
| CMP 70HX | 0x1EFC | 3D unlock |

### Turing CMP Series
|   GPU    | PCI ID | Features |
|----------|--------|-----------|
| CMP 50HX | 0x1EBC | 3D unlock |
| CMP 40HX | 0x1E49 | 3D unlock |
| CMP 30HX | 0x1E09 | 3D unlock |

### Pascal Mining Series
| GPU | PCI ID | Features |
|-----|--------|---------|
| P102-100 | 0x1B07 | 3D unlock |
| P104-100 | 0x1B87 | 3D unlock |
| P104-101 | 0x1C09 | 3D unlock |
| P106-100 | 0x1BC7 | 3D unlock |
| P106-090 | 0x1C07 | 3D unlock |

Additional supported IDs:  
`0x2082, 0x2083, 0x2089, 0x20C2, 0x20C3, 0x220D, 0x224D, 0x248A, 0x248D, and more`

---

## Installation

### Prerequisite
Secure Boot must be **disabled** in your system firmware (UEFI/BIOS).  
The patch modifies the `nvidia.ko` kernel module, which will not load if signature enforcement is enabled.

---

### Steps

```bash
git clone https://github.com/theneocorp/cmppatcher.git
cd cmppatcher

sudo install.sh