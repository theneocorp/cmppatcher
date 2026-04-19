"""
cmppatcher DNF plugin — re-applies NVIDIA patches after nvidia package updates.
Install to /etc/dnf/plugins/cmppatcher.py
"""

import subprocess
import dnf

NVIDIA_PKGS = {"nvidia-driver", "kmod-nvidia", "akmod-nvidia",
               "nvidia-kmod", "nvidia-dkms"}


class CmppatcherPlugin(dnf.Plugin):
    name = "cmppatcher"

    def transaction(self):
        try:
            changed = {
                p.name
                for p in self.base.transaction
                if p.action in (
                    dnf.transaction.PKG_INSTALL,
                    dnf.transaction.PKG_UPGRADE,
                )
            }
        except Exception:
            return

        if not (NVIDIA_PKGS & changed):
            return

        subprocess.run(
            ["/etc/cmppatcher/repatch.sh", "--auto"],
            capture_output=True,
        )
