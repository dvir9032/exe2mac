"""Mach-O reader (recompiler/macho.py) on synthetic images built here."""
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from recompiler.macho import MachO, MachOError  # noqa: E402

BASE = 0x100000000


def _seg(name, vm, vs, fo, fs, prot, sections=()):
    body = struct.pack("<16sQQQQiiII", name.encode(), vm, vs, fo, fs, prot, prot, len(sections), 0)
    for sname, addr, size, off in sections:
        body += struct.pack("<16s16sQQIIIIIIII", sname.encode(), name.encode(), addr, size, off, 0, 0, 0, 0, 0, 0, 0)
    return struct.pack("<II", 0x19, 8 + len(body)) + body


def build(fixups="opcodes"):
    """__TEXT (code at 0x1000) + __DATA (two pointers at 0x2000) + __LINKEDIT.
    Pointer 0 is rebased to __TEXT+0x1000; pointer 1 is bound to _puts."""
    code = bytes.fromhex("c3")
    linkedit_off = 0x3000
    if fixups == "opcodes":
        rebase = bytes([0x11, 0x22, 0x00, 0x51, 0x00])          # type ptr; seg 2 off 0; do 1; done
        bind = (bytes([0x11]) + bytes([0x40]) + b"_puts\0" + bytes([0x51, 0x72, 0x08, 0x90, 0x00]))
        le = rebase + bind
        dyld = struct.pack("<II10I", 0x80000022, 48, linkedit_off, len(rebase), linkedit_off + len(rebase),
                           len(bind), 0, 0, 0, 0, 0, 0)
        data = struct.pack("<QQ", BASE + 0x1000, 0)
    else:
        # chained fixups, DYLD_CHAINED_PTR_64_OFFSET: rebase (target 0x1000, next 2*4) then bind ordinal 0
        hdr_size = 28
        starts_off = hdr_size
        seg_starts = struct.pack("<I", 4) + struct.pack("<IIII", 0, 0, 4 * 5 + 0, 0)   # 4 segments; __DATA at +20
        per_seg = struct.pack("<IHHQIHH", 24, 0x1000, 6, 0x2000, 0, 1, 0)
        starts = seg_starts + per_seg
        imports_off = starts_off + len(starts)
        imports = struct.pack("<I", 1 | (0 << 9))                # lib ordinal 1, name offset 0
        symbols_off = imports_off + len(imports)
        symbols = b"_puts\0"
        header = struct.pack("<IIIIIII", 0, starts_off, imports_off, symbols_off, 1, 1, 0)
        le = header + starts + imports + symbols
        dyld = struct.pack("<IIII", 0x80000034, 16, linkedit_off, len(le))
        rebase_ptr = 0x1000 | (2 << 51)
        bind_ptr = (1 << 63) | 0
        data = struct.pack("<QQ", rebase_ptr, bind_ptr)
    cmds = [
        _seg("__PAGEZERO", 0, BASE, 0, 0, 0),
        _seg("__TEXT", BASE, 0x2000, 0, 0x2000, 5, [("__text", BASE + 0x1000, len(code), 0x1000)]),
        _seg("__DATA", BASE + 0x2000, 0x1000, 0x2000, 0x1000, 3, [("__data", BASE + 0x2000, 16, 0x2000)]),
        _seg("__LINKEDIT", BASE + 0x3000, 0x1000, linkedit_off, len(le), 1),
        struct.pack("<IIQQ", 0x80000028, 24, 0x1000, 0),                                   # LC_MAIN
        struct.pack("<IIIIII", 0x0C, 24 + 32, 24, 0, 0, 0) + b"/usr/lib/libSystem.B.dylib".ljust(32, b"\0"),
        dyld,
    ]
    blob = b"".join(cmds)
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, len(cmds), len(blob), 0x200085, 0)
    img = bytearray(0x3000 + len(le))
    img[:len(hdr) + len(blob)] = hdr + blob
    img[0x1000:0x1000 + len(code)] = code
    img[0x2000:0x2010] = data
    img[0x3000:] = le
    return bytes(img)


class MachOReaderTests(unittest.TestCase):
    def load(self, blob):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(blob)
        try:
            return MachO(f.name)
        finally:
            os.unlink(f.name)

    def check(self, m):
        self.assertEqual(m.image_base, BASE)
        self.assertEqual(m.entry_rva, 0x1000)
        self.assertEqual([s.name for s in m.sections], ["__TEXT", "__DATA"])
        self.assertTrue(m.sections[0].executable)
        self.assertFalse(m.sections[1].executable)
        self.assertEqual(m.relocs, [0x2000])
        self.assertEqual(m.u64(0x2000), BASE + 0x1000)           # rebased pointer holds the preferred VA
        self.assertEqual(m.imports, [(0x2008, "/usr/lib/libSystem.B.dylib", "_puts")])
        self.assertEqual(m.u64(0x2008), 0)                       # bound slot is filled by the loader

    def test_dyld_info_opcodes(self):
        self.check(self.load(build("opcodes")))

    def test_chained_fixups(self):
        self.check(self.load(build("chained")))

    def test_rejects_non_x86_64(self):
        blob = bytearray(build())
        blob[4:8] = struct.pack("<I", 0x0100000C)               # CPU_TYPE_ARM64
        with self.assertRaisesRegex(MachOError, "not x86-64"):
            self.load(bytes(blob))


if __name__ == "__main__":
    unittest.main()
