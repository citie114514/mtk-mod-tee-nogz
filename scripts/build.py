"""Hash-pinned, offline ATF NoGZ patches. No device or network operations."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
import unicorn as U
from unicorn import arm64_const as R

A, L, TAG = 0x48200000, 0x50F00000, 0x48600000
HIGH, STACK, H, STOP = 0xFFFF000000000000, 0x1000000, 0x1200000, 0x1800000
MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parts(data):
    result, off = {}, 0
    while off + 512 <= len(data):
        if struct.unpack_from("<I", data, off)[0] != 0x58881688:
            break
        size = struct.unpack_from("<I", data, off + 4)[0]
        name = data[off + 8:off + 40].split(b"\0")[0].decode("ascii")
        header = struct.unpack_from("<I", data, off + 52)[0]
        align = struct.unpack_from("<I", data, off + 68)[0]
        require(header == 512 and align == 16, "Unsupported image header")
        end = off + header + size
        require(end <= len(data), "Truncated image")
        if name not in ("cert1", "cert2"):
            require(name not in result, "Duplicate image group")
            result[name] = data[off + header:end]
        off = off + header + (size + align - 1) // align * align
    return result


def load_profile(name):
    raw = json.loads((Path(__file__).resolve().parents[1] / "references/profiles.json").read_text(encoding="utf-8"))
    p = raw[name]
    return {k: ([int(vv, 0) for vv in v] if isinstance(v, list)
                else int(v, 0) if v.startswith("0x") else v) for k, v in p.items()}


def branch(src, dst):
    require((dst - src) % 4 == 0 and -(1 << 27) <= dst - src < (1 << 27), "Branch out of range")
    return 0x14000000 | (((dst - src) // 4) & 0x3FFFFFF)


def patches(p):
    g, c = p["getter"], p["callback"]
    return [
        (p["pc_patch"], 0xF9400828, 0xD2A00000 | (0x50F0 << 5) | 8),
        (p["kernel_patch"], 0x1A8C01AC, 0x5280792C),
        (g, p["getter_before"][0], 0x52800000),
        (g + 4, p["getter_before"][1], 0xD65F03C0),
        (c, 0xB9400008, 0x52800028),
        (c + 8, 0x2A1F03E0, 0xB9000008),
        (c + 16, 0xD65F03C0, branch(c + 16, g + 8)),
        (g + 8, 0x2A2803E8, 0xD50B7A20),
        (g + 12, 0x12000100, 0xD5033F9F),
        (g + 16, 0xD65F03C0, branch(g + 16, g)),
    ]


def patch(data, p, base=0):
    result = bytearray(data)
    for off, before, after in patches(p):
        require(struct.unpack_from("<I", result, off + base)[0] == before,
                f"Original instruction mismatch at {off:#x}")
        struct.pack_into("<I", result, off + base, after)
    return bytes(result)


class Machine:
    """Actual code within explicit boundaries; not a hardware boot emulator."""

    def __init__(self, atf, lk, p):
        self.p = p
        self.uc = U.Uc(U.UC_ARCH_ARM64, U.UC_MODE_ARM)
        self.buffers = []
        for address, size, data, alias in (
            (A, 0x100000, atf, False), (L, 0x200000, lk, True),
            (TAG, 0x10000, b"", True),
        ):
            buffer = ctypes.create_string_buffer(size)
            require(len(data) <= size, "Image too large for test mapping")
            ctypes.memmove(buffer, data, len(data))
            self.buffers.append(buffer)
            self.uc.mem_map_ptr(address, size, U.UC_PROT_ALL, ctypes.addressof(buffer))
            if alias:
                self.uc.mem_map_ptr(HIGH | address, size, U.UC_PROT_ALL, ctypes.addressof(buffer))
        for addr in (STACK, H, STOP):
            self.uc.mem_map(addr, 0x20000)
        self.el, self.pfr = 1, 0x100
        self.events, self.allowed = [], []
        self.done = None
        self.uc.hook_add(U.UC_HOOK_CODE, self.code)

    def x(self, index, value=None):
        register = getattr(R, f"UC_ARM64_REG_X{index}")
        if value is None:
            return self.uc.reg_read(register)
        self.uc.reg_write(register, value)

    def read(self, addr, size):
        return bytes(self.uc.mem_read(addr, size))

    def word(self, addr, value=None, fmt="<I"):
        if value is None:
            return struct.unpack(fmt, self.read(addr, struct.calcsize(fmt)))[0]
        self.uc.mem_write(addr, struct.pack(fmt, value))

    def code(self, uc, pc, size, _):
        if pc in self.stops:
            self.done = pc
            uc.emu_stop()
            return
        require(any(lo <= pc < hi for lo, hi in self.allowed), f"Unmodelled PC {pc:#x}")
        word = self.word(pc)
        if word == 0xD5384244:
            self.x(4, self.el * 4)
        elif word == 0xD5380408:
            self.x(8, self.pfr)
        elif word in (0xD51C4024, 0xD51C4004, 0xD51C1149):
            self.events.append(("modeled_EL2_sysreg_write", pc))
        elif word == 0xD53E1149 and self.el == 2:
            self.done = "illegal_CPTR_EL3"
            uc.emu_stop()
            return
        elif word == 0xD50B7A20:
            self.events.append(("dc_cvac", self.x(0), self.word(self.x(0))))
        elif word == 0xD5033F9F:
            self.events.append(("dsb_sy",))
        else:
            return
        uc.reg_write(R.UC_ARM64_REG_PC, pc + 4)

    def run(self, start, ranges, args=(), stops=None, budget=20000):
        self.allowed, self.stops = ranges, {STOP} if stops is None else set(stops)
        self.done = None
        self.uc.reg_write(R.UC_ARM64_REG_SP, STACK + 0x10000)
        self.x(30, STOP)
        for i, value in enumerate(args):
            self.x(i, value)
        self.uc.emu_start(start, STOP + 4, count=budget)
        require(self.done is not None, "Instruction budget exhausted")
        return self.done

    def ar(self, key):
        lo, hi = self.p[key]
        return A + lo, A + hi

    def setup(self, flags=0, last=False):
        info = struct.pack("<III", 12, 0x88610023, flags)
        other = struct.pack("<IIII", 16, 0x12345678, 0xBEEF, 0xCAFE)
        data = (other + info if last else info + other) + bytes(8)
        self.uc.mem_write(TAG, data)
        for addr, value in ((H, TAG), (H + 8, 0x1234), (H + 16, 0x87F800000),
                            (A + self.p["handoff_global"], H)):
            self.word(addr, value, "<Q")
        return data, TAG + (24 if last else 8)

    def tags(self):
        p = self.p
        self.run(A + p["tag_parser"][0],
                 [self.ar("tag_parser"), self.ar("args_getter"),
                  (A + p["callback"], A + p["callback"] + 20),
                  (A + p["getter"], A + p["getter"] + 20)])
        lo, hi = p["lk_parser"]
        callback = HIGH + L + p["lk_callback"]
        self.run(L + lo, [(L + lo, L + hi), (callback, callback + 16)])

    def gate(self):
        g, start = self.p["lk_getter"], self.p["lk_gate"]
        return self.run(L + start, [(L + start, L + start + 8), (L + g, L + g + 20)],
                        stops={L + start + 8, L + self.p["lk_skip"]})

    def cold(self):
        g, ep = self.p["getter"], A + self.p["ep"]
        self.run(A + self.p["cold"][0],
                 [self.ar("cold"), self.ar("cold_helpers"), (A + g, A + g + 20)], (ep, H))
        return self.word(ep + 8, fmt="<Q"), self.word(ep + 16)

    def entry(self, el=1):
        self.el = el
        ranges = [(L, L + 8)] + [(L + lo, L + hi) for lo, hi in
                                (self.p["lk_stack"], self.p["lk_elcheck"])]
        return self.run(L, ranges, stops={L + 8})

    def kernel(self, a64=1, pfr=0x100):
        self.pfr = pfr
        g, ep = self.p["getter"], A + self.p["ep"]
        for i, value in enumerate((0x40080000, 0x44000000, 0x1000)):
            self.word(A + self.p["kernel_args"] + 8 * i, value, "<Q")
        lo, hi = self.ar("kernel")
        self.run(lo, [(lo, hi), (A + g, A + g + 20)], (a64,), stops={hi, STOP})
        return self.word(ep + 8, fmt="<Q"), self.word(ep + 16)


def regression(original, candidate, lk, p):
    results = []
    require(candidate == patch(original, p), "Unexpected ATF changes")
    off = p["pc_patch"]
    ins = next(MD.disasm(candidate[off:off + 4], A + off))
    require(ins.op_str == "x8, #0x50f00000", "Wrong PC opcode decode")
    for last in (False, True):
        for flags in (0, 1, 2, 0xFFFFFFFF):
            m = Machine(candidate, lk, p)
            before, pointer = m.setup(flags, last)
            m.tags()
            expected = bytearray(before)
            struct.pack_into("<I", expected, pointer - TAG, 1)
            require(m.read(TAG, len(before)) == expected, "Tag bounds/update failure")
            require(m.word(A + p["flag"]) == 1, "ATF flag not synchronized")
            require(m.events.index(("dc_cvac", pointer, 1)) <
                    m.events.index(("dsb_sy",)), "Cache clean/barrier missing")
            require(m.cold() == (L, 0x3C5), "Wrong cold PC/SPSR")
            require(m.entry() == L + 8, "LK EL1 entry failed")
            require(m.gate() == L + p["lk_skip"], "LK still enters GZ unmap")
            require(m.kernel() == (0x40080000, 0x3C9), "Kernel PC/SPSR wrong")
            results.append(f"shared_chain flags={flags:#x} tag_last={last}")
    m = Machine(candidate, lk, p)
    m.setup()
    m.uc.mem_write(TAG, bytes(8))
    m.tags()
    require(m.gate() == L + p["lk_skip"], "Missing-tag defaults wrong")
    results.append("missing_tag_defaults")
    require(Machine(candidate, lk, p).entry(2) == "illegal_CPTR_EL3", "EL2 negative control failed")
    results.append("LK_EL2_illegal_EL3_negative_control")
    for a64, pfr, spsr in ((1, 0, 0x3C9), (1, 0x200, 0x3C9), (0, 0x100, 0x1DA)):
        require(Machine(candidate, lk, p).kernel(a64, pfr) == (0x40080000, spsr),
                "Kernel mode control failed")
    results.append("kernel_feature_and_AArch32_controls")
    bad = bytearray(candidate)
    struct.pack_into("<I", bad, p["pc_patch"], 0xD2A21E08)
    m = Machine(bytes(bad), lk, p)
    m.setup()
    require(m.cold() == (0x10F00000, 0x3C5), "Bad-PC negative control failed")
    results.append("wrong_PC_negative_control")
    bad = bytearray(candidate)
    c = p["callback"]
    bad[c:c + 20] = original[c:c + 20]
    m = Machine(bytes(bad), lk, p)
    m.setup()
    m.tags()
    require(m.gate() == L + p["lk_gate"] + 8, "Stale-tag negative control failed")
    results.append("missing_tag_sync_negative_control")
    m = Machine(candidate, lk, p)
    try:
        m.run(A + p["cold"][0], [m.ar("cold")], budget=1)
    except ValueError as error:
        require(str(error) == "Instruction budget exhausted", "Unexpected negative-control failure")
    else:
        raise ValueError("Budget exhaustion was accepted")
    results.append("budget_exhaustion_rejected")
    return results

def run_tool(tools, name, args, output):
    result = subprocess.run([sys.executable, str(tools / name), *map(str, args)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            encoding="utf-8", errors="replace",
                            env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    output.write_text(result.stdout, encoding="utf-8")
    require(result.returncode == 0, f"{name} failed; inspect {output}")
    return result.stdout


def cert_mode_flags(status):
    if status == "NEW_PARSER":
        return []
    if status == "LEGACY":
        return ["--legacy"]
    raise ValueError(f"Certificate mode is not conclusive: {status}; manual analysis required")


def sign_all_flag(tools):
    """Extra sign_mtk_cert.py flags that the supported tool build always takes.

    The signing flow runs every image group of the container in one pass, so `--all` is not
    optional for the sign_mtk_cert.py this project is written against: the manual already
    documents `--all -w` for NEW_PARSER and `--legacy --all -w` for LEGACY, and
    verify_mtk_image.py is then asked for two `Result: VALID` groups.

    Kept as a named hook (rather than inlined at the call site) so that a tool copy which
    does not know the option can be handled here without touching `main()`.
    """
    return ["--all"]


def detect_signing_mode(preloader, output_dir):
    require(preloader.stat().st_size <= 32 * 1024 * 1024, "Preloader exceeds detector size limit")
    original_hash = sha(preloader.read_bytes())
    text = run_tool(
        Path(__file__).resolve().parent, "detect_pl_cert_mode.py",
        [preloader, "--json", "--report", output_dir / "cert-mode.txt"],
        output_dir / "detect.log",
    )
    result = json.loads(text)
    records = result.get("results")
    require(isinstance(records, list) and len(records) == 1, "Expected one detector result")
    detection = records[0]
    cert_mode_flags(detection.get("status"))
    require(Path(detection["path"]).resolve() == preloader.resolve(), "Detector input path mismatch")
    require(detection.get("sha256") == original_hash, "Detector input hash mismatch")
    require(sha(preloader.read_bytes()) == original_hash, "Preloader changed during detection")
    return detection


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=["yunluo", "peral", "xaga"], required=True)
    parser.add_argument("--tee", type=Path, required=True)
    parser.add_argument("--lk", type=Path, required=True)
    parser.add_argument("--preloader", type=Path, help="matching preloader; required when signing")
    parser.add_argument("--tools", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    p = load_profile(args.profile)
    source, source_lk = args.tee.read_bytes(), args.lk.read_bytes()
    require(sha(source) == p["tee_sha256"], "Unknown tee SHA256; do not apply this profile")
    require(sha(source_lk) == p["lk_sha256"], "Unknown LK SHA256; do not apply this profile")
    stock, lk = parts(source), parts(source_lk)["lk"]
    require(set(stock) == {"atf", "tee"}, "Unexpected tee groups")
    modified = patch(stock["atf"], p)
    checks = regression(stock["atf"], modified, lk, p)
    if args.check_only:
        print(json.dumps({"profile": args.profile, "passed_checks": checks,
                          "cert_mode": None, "device_tested": False}, indent=2))
        return
    require(args.tools is not None and args.out_dir is not None and args.preloader is not None,
            "--tools, --out-dir and --preloader required when signing")
    require(not args.out_dir.exists(), "Output directory exists; choose a fresh directory")
    for tool in ("sign_mtk_cert.py", "verify_mtk_image.py"):
        require((args.tools / tool).is_file(), f"Missing {tool}")
    args.out_dir.mkdir(parents=True)
    detection = detect_signing_mode(args.preloader, args.out_dir)
    flags = cert_mode_flags(detection["status"])
    mode = "legacy" if flags else "new"
    unsigned, final = args.out_dir / "tee.unsigned.img", args.out_dir / f"tee_nogz_{mode}.img"
    unsigned.write_bytes(patch(source, p, 512))
    all_flag = sign_all_flag(args.tools)
    run_tool(args.tools, "sign_mtk_cert.py",
             [unsigned, *flags, *all_flag, "-w", "-o", final], args.out_dir / "sign.log")
    output = run_tool(args.tools, "verify_mtk_image.py", ["--all", final], args.out_dir / "verify.log")
    require(output.count("Result: VALID") == 2, "Expected two VALID image groups")
    signed = parts(final.read_bytes())
    require(set(signed) == {"atf", "tee"}, "Signed group mismatch")
    require(signed["tee"] == stock["tee"], "TEE executable data changed")
    checks = regression(stock["atf"], signed["atf"], lk, p)
    require(args.tee.read_bytes() == source and args.lk.read_bytes() == source_lk, "Input changed")
    require(sha(args.preloader.read_bytes()) == detection["sha256"], "Preloader changed")
    instructions = []
    for off, _, _ in patches(p):
        ins = next(MD.disasm(signed["atf"][off:off + 4], A + off))
        instructions.append(f"{ins.address:#x}: {ins.bytes.hex()} {ins.mnemonic} {ins.op_str}")
    (args.out_dir / "disassembly.txt").write_text("\n".join(instructions), encoding="utf-8")
    report = {
        "profile": args.profile, "input_tee_sha256": sha(source), "input_lk_sha256": sha(source_lk),
        "output": str(final.resolve()), "output_size": final.stat().st_size,
        "output_sha256": sha(final.read_bytes()), "passed_checks": checks,
        "cert_mode": mode, "signing_mode_flags": flags,
        "sign_tool_all_flag": bool(all_flag),
        "input_preloader_sha256": detection["sha256"],
        "cert_detection": {key: detection.get(key) for key in ("status", "isa", "reason")},
        "cert_detection_report": "cert-mode.txt",
        "historical_output_cert_mode": p.get("historical_output_cert_mode"),
        "historical_output_matches": (sha(final.read_bytes()) == p.get("historical_output_sha256")
                                      if mode == p.get("historical_output_cert_mode") else None),
        "device_tested": False, "scope": "Bounded instruction regression, not full boot or hardware verification",
        "patches": [{"atf_offset": hex(o), "file_offset": hex(o + 512),
                     "before": hex(b), "after": hex(a)} for o, b, a in patches(p)],
        "tool_hashes": {
            **{name: sha((args.tools / name).read_bytes())
               for name in ("sign_mtk_cert.py", "verify_mtk_image.py")},
            "detect_pl_cert_mode.py": sha(
                (Path(__file__).resolve().parent / "detect_pl_cert_mode.py").read_bytes()),
        },
    }
    (args.out_dir / "manifest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
