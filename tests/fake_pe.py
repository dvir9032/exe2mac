"""In-memory PE-like image for translator tests (no file on disk needed).

Layout: headers at RVA 0, .text at RVA 0x1000 (entry), .rdata at 0x2000,
.data at 0x3000 (RW). Mirrors the attributes of recompiler.pe.PE that the
CFG discovery and lifter use.
"""
import struct

BASE = 0x140000000
TEXT_RVA, RDATA_RVA, DATA_RVA = 0x1000, 0x2000, 0x3000


class _Sec:
    def __init__(self, name, vaddr, vsize, chars):
        self.name, self.vaddr, self.vsize, self.raw_size, self.chars = name, vaddr, vsize, vsize, chars

    @property
    def executable(self):
        return bool(self.chars & 0x20000000)


class FakePE:
    def __init__(self, code: bytes, rdata: bytes = b"", imports=(), relocs=()):
        self.image_base = BASE
        self.entry_rva = TEXT_RVA
        self.size_of_image = 0x4000
        self.size_of_headers = 0x400
        self.section_alignment = 0x1000
        self.image = bytearray(self.size_of_image)
        self.image[:2] = b"MZ"
        self.image[TEXT_RVA:TEXT_RVA + len(code)] = code
        self.image[RDATA_RVA:RDATA_RVA + len(rdata)] = rdata
        self.sections = [
            _Sec(".text", TEXT_RVA, len(code), 0x60000020),
            _Sec(".rdata", RDATA_RVA, max(len(rdata), 1), 0x40000040),
            _Sec(".data", DATA_RVA, 0x10, 0xC0000040),
        ]
        self.imports = list(imports)
        self.relocs = list(relocs)

    def u64(self, rva):
        return struct.unpack_from("<Q", self.image, rva)[0]
