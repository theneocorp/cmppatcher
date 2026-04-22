#!/usr/bin/env python3
"""
cmppatcher FMA Rewriter Daemon — runs as a systemd service.

Listens on a Unix socket and rewrites NVIDIA SASS cubins to replace every
FFMA (fused multiply-add) instruction with an FMUL+FADD pair, bypassing the
16:1 hardware throttle on the CMP 170HX (GA100-105F).

SASS rewriting logic adapted from jonpry/sass_fma/rewriter.py.
Requires: nvdisasm (from CUDA toolkit) and CuAssembler (pip install CuAssembler).

Protocol:
  Request:  [uint32_t length, BE][cubin bytes]
  Response: [uint32_t length, BE][rewritten cubin bytes]
            length == 0 if no FMA instructions were found or rewrite failed
"""

import argparse
import glob
import logging
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# CuAssembler import (optional — warn at startup if missing)
# ---------------------------------------------------------------------------

try:
    import importlib.util as _ilu
    _cc_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "CuAssembler", "CuAsm", "CuControlCode.py")
    _spec = _ilu.spec_from_file_location("CuControlCode", _cc_path)
    _mod = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    CuControlCode = _mod.CuControlCode
    HAS_CUASM = True
except Exception:
    HAS_CUASM = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [rewriter_daemon] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SASS rewriter (adapted from jonpry/sass_fma rewriter.py)
# ---------------------------------------------------------------------------

class SassRewriter:
    def __init__(self, arch: str = "sm_80"):
        self.arch = arch

    def disassemble(self, cubin_path: str) -> str:
        nvdisasm = _find_nvdisasm()
        if not nvdisasm:
            raise RuntimeError("nvdisasm not found")
        result = subprocess.run(
            [nvdisasm, "-hex", cubin_path],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"nvdisasm failed: {result.stderr[:200]}")
        return result.stdout

    def rewrite(self, cubin_bytes: bytes) -> bytes:
        with tempfile.NamedTemporaryFile(suffix=".cubin", delete=False) as f:
            f.write(cubin_bytes)
            tmp_in = f.name
        tmp_out = tmp_in + ".out.cubin"

        try:
            sass = self.disassemble(tmp_in)
            if not sass:
                return b""

            # Auto-detect SM architecture from disassembly text.
            # Keep sm_80 as default for GA100/CMP 170HX and avoid forcing sm_70
            # unless the disassembly explicitly indicates a pre-sm80 target.
            # Temporary hard-force for CMP 170HX / GA100 host: always rewrite as sm_80.
            # The auto-detect path can mis-detect mixed nvdisasm text and choose sm_70.
            self.arch = "sm_80"

            sections, pc_map, max_reg, n_replaced = self._parse_and_rewrite(sass)
            if n_replaced == 0:
                return b""

            result = self._rebuild_elf(cubin_bytes, sections, pc_map, max_reg)
            log.info("Rewrote %d FFMA → FMUL+FADD (arch=%s)", n_replaced, self.arch)
            return result
        finally:
            os.unlink(tmp_in)
            if os.path.exists(tmp_out):
                os.unlink(tmp_out)

    # ------------------------------------------------------------------
    # Internal SASS parsing (adapted from jonpry)
    # ------------------------------------------------------------------

    def _get_regs(self, op: str, args: str):
        regs = [int(r) for r in re.findall(r"R(\d+)", args)]
        if not regs:
            return set(), set()
        if any(x in op for x in ["ST", "BRA", "EXIT", "RET", "JMP", "CAL", "BAR", "MEMBAR"]):
            return set(), set(regs)
        return {regs[0]}, set(regs[1:])

    def _solve_liveness(self, instrs: list) -> None:
        pc_to_idx = {ins["pc"]: i for i, ins in enumerate(instrs)}
        for i, ins in enumerate(instrs):
            succs = []
            if "EXIT" not in ins["op"] and "RET" not in ins["op"] and i + 1 < len(instrs):
                succs.append(i + 1)
            if any(x in ins["op"] for x in ["BRA", "JMP"]):
                off = struct.unpack("<i", struct.pack("<I", (ins["h1"] >> 32) & 0xFFFFFFFF))[0]
                target = ins["pc"] + 16 + off
                if target in pc_to_idx:
                    succs.append(pc_to_idx[target])
            ins["succs"] = succs
            ins["live_in"] = set()
            ins["live_out"] = set()

        changed = True
        while changed:
            changed = False
            for i in reversed(range(len(instrs))):
                ins = instrs[i]
                new_out = set()
                for s_idx in ins["succs"]:
                    new_out.update(instrs[s_idx]["live_in"])
                new_in = ins["uses"].union(new_out - ins["defs"])
                if new_in != ins["live_in"] or new_out != ins["live_out"]:
                    ins["live_in"] = new_in
                    ins["live_out"] = new_out
                    changed = True

    def _parse_and_rewrite(self, raw_text: str):
        max_reg = 0
        for r in re.findall(r"R(\d+)", raw_text):
            max_reg = max(max_reg, int(r))

        sec_re = re.compile(r"//-+\s+(?P<name>\.text\.\S+)\s+-+")
        ins_re = re.compile(
            r"/\*(?P<pc>[0-9a-f]+)\*/\s+(?:@!?[A-Z0-9]+\s+)?(?P<op>[\w\.]+)"
            r"(?P<args>[^;]*);\s+/\*\s+(?P<h1>0x[0-9a-f]+)\s+\*/"
        )

        sections: dict[str, list] = {}
        pc_map: dict[tuple, int] = {}
        cur_sec = ".text"
        n_replaced = 0

        lines = raw_text.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            s_m = sec_re.search(line)
            if s_m:
                cur_sec = s_m.group("name")
                sections[cur_sec] = []
                i += 1
                continue
            m = ins_re.search(line)
            if m:
                if cur_sec not in sections:
                    sections[cur_sec] = []
                pc   = int(m.group("pc"), 16)
                op   = m.group("op")
                args = m.group("args")
                h1   = int(m.group("h1"), 16)
                i += 1
                h2 = 0
                if i < len(lines):
                    h2_m = re.search(r"/\*\s+(0x[0-9a-f]+)\s+\*/", lines[i])
                    if h2_m:
                        h2 = int(h2_m.group(1), 16)
                defs, uses = self._get_regs(op, args)
                sections[cur_sec].append({
                    "pc": pc, "h1": h1, "h2": h2,
                    "op": op, "defs": defs, "uses": uses, "old_pc": pc,
                })
            else:
                i += 1

        for sn, instrs in sections.items():
            self._solve_liveness(instrs)
            new_instrs = []
            for ins in instrs:
                pc_map[(sn, ins["pc"])] = len(new_instrs) * 16

                if "FMA" in ins["op"] and self.arch in ("sm_70", "sm_80"):
                    n_replaced += 1
                    rd = (ins["h1"] >> 16) & 0xFF
                    ra = (ins["h1"] >> 24) & 0xFF
                    h1_pred  = ins["h1"] & 0xF000
                    op_base  = ins["h1"] & 0xFFF

                    # Allocate a temporary register from the dead set
                    candidates = (set(range(max_reg + 1))
                                  - ins["live_out"] - ins["defs"] - ins["uses"])
                    temp_reg = min(candidates) if candidates else max_reg + 1
                    if temp_reg > max_reg:
                        max_reg = temp_reg

                    orig_ctrl = ins["h2"] >> 41
                    if HAS_CUASM:
                        c_wait, c_read, c_write, c_yield, c_stall = \
                            CuControlCode.splitCode(orig_ctrl)
                        fmul_ctrl = CuControlCode.mergeCode(c_wait, c_read, 7, 1, 4)
                        fadd_ctrl = CuControlCode.mergeCode(0, 7, c_write, c_yield, c_stall)
                    else:
                        # Fallback: preserve original control bits on both instructions
                        fmul_ctrl = orig_ctrl
                        fadd_ctrl = orig_ctrl

                    fmul_h2 = (fmul_ctrl << 41) | 0x00400000
                    fadd_h2 = (fadd_ctrl << 41)

                    if op_base == 0x423:  # FFMA rd, ra, rb, imm
                        rb      = ins["h2"] & 0xFF
                        imm_val = (ins["h1"] >> 32) & 0xFFFFFFFF
                        fmul_h1 = (rb << 32) | (ra << 24) | (temp_reg << 16) | 0x220 | h1_pred
                        fadd_h1 = (imm_val << 32) | (temp_reg << 24) | (rd << 16) | 0x421 | h1_pred
                    elif op_base == 0x823:  # FFMA rd, ra, imm, rc
                        rc      = ins["h2"] & 0xFF
                        imm_val = (ins["h1"] >> 32) & 0xFFFFFFFF
                        fmul_h1 = (imm_val << 32) | (ra << 24) | (temp_reg << 16) | 0x820 | h1_pred
                        fadd_h1 = (temp_reg << 32) | (rc << 24) | (rd << 16) | 0x221 | h1_pred
                    else:  # 0x223: FFMA rd, ra, rb, rc
                        rb = (ins["h1"] >> 32) & 0xFF
                        rc = ins["h2"] & 0xFF
                        fmul_h1 = (rb << 32) | (ra << 24) | (temp_reg << 16) | 0x220 | h1_pred
                        fadd_h1 = (temp_reg << 32) | (rc << 24) | (rd << 16) | 0x221 | h1_pred

                    new_instrs.append({"h1": fmul_h1, "h2": fmul_h2,
                                       "op": "FMUL", "old_pc": ins["pc"]})
                    new_instrs.append({"h1": fadd_h1, "h2": fadd_h2,
                                       "op": "FADD", "old_pc": None})
                else:
                    new_instrs.append({
                        "h1": ins["h1"], "h2": ins["h2"],
                        "op": ins["op"],  "old_pc": ins["pc"],
                    })
            sections[sn] = new_instrs

        return sections, pc_map, max_reg, n_replaced

    def _rebuild_elf(self, original: bytes, sections: dict,
                     pc_map: dict, max_reg: int) -> bytes:
        data      = bytearray(original)
        e_phoff   = struct.unpack_from("<Q", data, 32)[0]
        e_shoff   = struct.unpack_from("<Q", data, 40)[0]
        e_phnum   = struct.unpack_from("<H", data, 56)[0]
        e_shnum   = struct.unpack_from("<H", data, 60)[0]
        sh_idx    = struct.unpack_from("<H", data, 62)[0]

        SHDR_FMT  = "<IIQQQQIIQQ"
        SHDR_SIZE = 64
        PHDR_FMT  = "<IIQQQQQQ"
        PHDR_SIZE = 56

        sh_table = [list(struct.unpack_from(SHDR_FMT, data, e_shoff + i * SHDR_SIZE))
                    for i in range(e_shnum)]
        ph_table = [list(struct.unpack_from(PHDR_FMT, data, e_phoff + i * PHDR_SIZE))
                    for i in range(e_phnum)]
        str_off  = sh_table[sh_idx][4]

        def get_name(idx):
            end = data.find(b"\x00", str_off + idx)
            return data[str_off + idx: end].decode("utf-8", errors="replace")

        # Fix branch offsets first
        for sn, instrs in sections.items():
            for i, ins in enumerate(instrs):
                if any(br in ins["op"] for br in ["BRA", "SSY", "PBK", "JMP"]):
                    off = struct.unpack("<i", struct.pack("<I", (ins["h1"] >> 32) & 0xFFFFFFFF))[0]
                    if ins["old_pc"] is not None:
                        target = ins["old_pc"] + 16 + off
                        if (sn, target) in pc_map:
                            new_off = pc_map[(sn, target)] - (i * 16 + 16)
                            ins["h1"] = (ins["h1"] & 0x00000000FFFFFFFF) | (
                                (new_off & 0xFFFFFFFF) << 32
                            )

        # Patch each .text section in-place, adjusting offsets
        for i in range(e_shnum):
            name = get_name(sh_table[i][0])
            if name not in sections:
                continue
            old_off  = sh_table[i][4]
            old_size = sh_table[i][5]
            new_sec  = bytearray()
            for ins in sections[name]:
                new_sec.extend(struct.pack("<QQ", ins["h1"], ins["h2"]))
            growth = len(new_sec) - old_size

            data = data[:old_off] + new_sec + data[old_off + old_size:]
            sh_table[i][5] = len(new_sec)
            if ".text." in name:
                # Update max register count field in sh_info upper byte
                sh_table[i][7] = (sh_table[i][7] & 0x00FFFFFF) | ((max_reg + 1) << 24)

            # Shift all subsequent sections and segments
            for j in range(e_shnum):
                if sh_table[j][4] > old_off:
                    sh_table[j][4] += growth
            for j in range(e_phnum):
                p_off   = ph_table[j][2]
                p_filesz = ph_table[j][5]
                if p_off <= old_off < p_off + p_filesz:
                    ph_table[j][5] += growth
                    ph_table[j][6] += growth
                elif p_off > old_off:
                    ph_table[j][2] += growth

            if e_phoff > old_off:
                e_phoff += growth
            if e_shoff > old_off:
                e_shoff += growth

        # Write back headers
        struct.pack_into("<QQ", data, 32, e_phoff, e_shoff)
        for i in range(e_shnum):
            struct.pack_into(SHDR_FMT, data, e_shoff + i * SHDR_SIZE, *sh_table[i])
        for i in range(e_phnum):
            struct.pack_into(PHDR_FMT, data, e_phoff + i * PHDR_SIZE, *ph_table[i])

        return bytes(data)


# ---------------------------------------------------------------------------
# nvdisasm location helper
# ---------------------------------------------------------------------------

def _find_nvdisasm() -> str | None:
    found = shutil.which("nvdisasm")
    if found:
        return found
    for p in sorted(glob.glob("/usr/local/cuda*/bin/nvdisasm"), reverse=True):
        if os.access(p, os.X_OK):
            return p
    return None


# ---------------------------------------------------------------------------
# Socket server
# ---------------------------------------------------------------------------

def handle_client(conn: socket.socket, rewriter: SassRewriter) -> None:
    try:
        # Read request length
        len_data = _recv_exact(conn, 4)
        if not len_data:
            return
        req_len = struct.unpack("!I", len_data)[0]
        if req_len == 0 or req_len > 256 * 1024 * 1024:
            conn.sendall(struct.pack("!I", 0))
            return

        cubin = _recv_exact(conn, req_len)
        if not cubin or len(cubin) != req_len:
            conn.sendall(struct.pack("!I", 0))
            return

        try:
            result = rewriter.rewrite(cubin)
        except Exception as e:
            log.warning("Rewrite failed: %s", e)
            result = b""

        if result:
            conn.sendall(struct.pack("!I", len(result)))
            conn.sendall(result)
        else:
            conn.sendall(struct.pack("!I", 0))
    except Exception as e:
        log.warning("Client error: %s", e)
    finally:
        conn.close()


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


def run_server(socket_path: str) -> None:
    rewriter = SassRewriter()

    if not _find_nvdisasm():
        log.error("nvdisasm not found — FMA rewriting disabled.")
        log.error("Install the CUDA toolkit to enable the FMA bypass.")
        sys.exit(1)

    if not HAS_CUASM:
        log.warning("CuAssembler not found — control codes will be approximated.")
        log.warning("Install with: pip3 install CuAssembler")

    # Clean up stale socket
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(socket_path)
    os.chmod(socket_path, 0o666)
    srv.listen(16)
    log.info("Listening on %s", socket_path)

    try:
        while True:
            conn, _ = srv.accept()
            handle_client(conn, rewriter)
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="cmppatcher FMA rewriter daemon"
    )
    ap.add_argument(
        "--socket",
        default="/var/run/cmppatcher-rewriter.sock",
        help="Unix socket path",
    )
    ap.add_argument(
        "--cache-dir",
        default="/etc/cmppatcher/cache",
        help="Cubin cache directory",
    )
    args = ap.parse_args()

    os.makedirs(args.cache_dir, exist_ok=True)
    os.chmod(args.cache_dir, 0o1777)
    run_server(args.socket)


if __name__ == "__main__":
    main()
