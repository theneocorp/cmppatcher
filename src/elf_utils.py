"""
Minimal ELF64 parser using stdlib struct only.

We only need to enumerate non-executable allocated data sections
(.rodata, .data, .data.rel.ro, etc.) — the regions where NVIDIA
stores device ID tables.  Scanning .text as well would produce
thousands of false-positive matches for Pascal device IDs.
"""

import struct
from typing import List, Tuple

# ELF section-header field offsets (64-bit)
# struct Elf64_Shdr { uint32 sh_name; uint32 sh_type; uint64 sh_flags;
#                     uint64 sh_addr; uint64 sh_offset; uint64 sh_size;
#                     uint32 sh_link; uint32 sh_info; uint64 sh_addralign;
#                     uint64 sh_entsize; }
_SHDR_FMT  = "<IIQQQQIIQQ"
_SHDR_SIZE = struct.calcsize(_SHDR_FMT)  # 64 bytes

SHT_PROGBITS  = 1
SHF_WRITE     = 1 << 0
SHF_ALLOC     = 1 << 1
SHF_EXECINSTR = 1 << 2


class ELF64:
    def __init__(self, data: bytes | bytearray):
        self._data = data
        if data[:4] != b"\x7fELF":
            raise ValueError("Not an ELF file")
        if data[4] != 2:
            raise ValueError("Not a 64-bit ELF")

        # ELF64 header fields starting at offset 16 (after the 16-byte e_ident)
        # <HH I QQQ I HHHHHH>
        # e_type e_machine e_version e_entry e_phoff e_shoff
        # e_flags e_ehsize e_phentsize e_phnum e_shentsize e_shnum e_shstrndx
        (self._e_type, self._e_machine, self._e_version,
         self._e_entry, self._e_phoff, self._e_shoff,
         self._e_flags, self._e_ehsize, self._e_phentsize,
         self._e_phnum, self._e_shentsize, self._e_shnum,
         self._e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)

    def _shdr(self, idx: int) -> tuple:
        off = self._e_shoff + idx * self._e_shentsize
        return struct.unpack_from(_SHDR_FMT, self._data, off)

    def get_data_sections(self) -> List[Tuple[int, int]]:
        """
        Return (file_offset, size) for every section that is:
          - SHT_PROGBITS (real data, not BSS/NOBITS)
          - SHF_ALLOC    (present in the loaded image)
          - NOT SHF_EXECINSTR (not executable — exclude .text)

        These are the only sections that can legitimately contain
        device-ID tables.  Scanning .text produces ~1200 false
        positives per Pascal device ID due to x86 instruction encoding.
        """
        results = []
        for i in range(self._e_shnum):
            (sh_name, sh_type, sh_flags, sh_addr,
             sh_offset, sh_size, sh_link, sh_info,
             sh_addralign, sh_entsize) = self._shdr(i)

            if sh_type != SHT_PROGBITS:
                continue
            if not (sh_flags & SHF_ALLOC):
                continue
            if sh_flags & SHF_EXECINSTR:
                continue
            if sh_size == 0:
                continue

            results.append((sh_offset, sh_size))
        return results

    def get_elf_end(self) -> int:
        """
        Return the byte offset just past the last ELF structural byte
        (end of the section-header table).  Everything after this is
        appended data — typically a PKCS#7 module signature on Linux
        kernel modules.  Truncating here strips that signature, which
        would be invalidated by patching anyway.
        """
        return self._e_shoff + self._e_shnum * self._e_shentsize
