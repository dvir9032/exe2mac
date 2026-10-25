"""Minimal Mach-O 64-bit (x86-64) reader for exe2mac.

Presents an Intel macOS executable through the same interface as ``pe.PE``
(image_base, entry_rva, sections, image, imports, relocs, ...) so the
decoder, CFG discovery and the gap report work unchanged.

Supported:
* thin x86-64 MH_EXECUTE images and the x86-64 slice of a universal (fat) file;
* LC_SEGMENT_64 (segments are presented as sections, with their protections);
* LC_MAIN entry point;
* both dyld fixup encodings, decoded at load-analysis time into
  - ``relocs``:  RVAs of 64-bit pointers that must be slid by (base - preferred),
    with the preferred-base target already written into ``image``;
  - ``imports``: (slot RVA, dylib, symbol) for every bound pointer (GOT,
    lazy pointers, data), the slot itself left as 0 in ``image``;
  * LC_DYLD_INFO(_ONLY) rebase and bind opcode streams (incl. lazy binds),
  * LC_DYLD_CHAINED_FIXUPS (DYLD_CHAINED_PTR_64 and _64_OFFSET, import
    formats 1-3);
* LC_FUNCTION_STARTS (exposed as ``function_starts``, RVAs).

Anything else that affects loading (other pointer formats, weak/flat
lookups by ordinal, threaded binds) raises MachOError: fail closed.
Structure layouts follow Apple's public <mach-o/loader.h>,
<mach-o/fixup-chains.h> (APSL) - definitions only, no code copied.
"""
from __future__ import annotations

import struct

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
CPU_TYPE_X86_64 = 0x01000007
MH_EXECUTE = 2

LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LAZY_LOAD_DYLIB = 0x20
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_MAIN = 0x80000028
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_FUNCTION_STARTS = 0x26
LC_UNIXTHREAD = 0x05

VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE = 1, 2, 4


class MachOError(ValueError):
    pass


class Segment:
    """Mimics pe.Section: a mapped range with protections."""

    def __init__(self, name, vaddr, vsize, raw_off, raw_size, prot, sections):
        self.name, self.vaddr, self.vsize = name, vaddr, vsize
        self.raw_off, self.raw_size, self.prot = raw_off, raw_size, prot
        self.sections = sections            # [(sectname, rva, size)]
        # PE-style characteristics so existing code can test them
        self.chars = ((0x20000020 if prot & VM_PROT_EXECUTE else 0) |
                      (0x40000000 if prot & VM_PROT_READ else 0) |
                      (0x80000000 if prot & VM_PROT_WRITE else 0))

    @property
    def executable(self):
        return bool(self.prot & VM_PROT_EXECUTE)

    def __repr__(self):
        return f"<Segment {self.name} rva=0x{self.vaddr:x} size=0x{self.vsize:x} prot={self.prot}>"


def _uleb(d, p):
    v = shift = 0
    while True:
        b = d[p]
        p += 1
        v |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return v, p


def _sleb(d, p):
    v = shift = 0
    while True:
        b = d[p]
        p += 1
        v |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            if b & 0x40:
                v -= 1 << shift
            return v, p


def _cstr(d, p):
    e = d.index(b"\0", p)
    return d[p:e].decode("utf-8", "replace"), e + 1


class MachO:
    format = "macho"

    def __init__(self, path):
        with open(path, "rb") as f:
            data = f.read()
        self.data = self._thin(data)
        d = self.data
        magic, cpu, _sub, ftype, ncmds, _size, self.flags, _r = struct.unpack_from("<IiiIIIII", d, 0)
        if magic != MH_MAGIC_64:
            raise MachOError("not a 64-bit Mach-O file")
        if cpu & 0xFFFFFFFF != CPU_TYPE_X86_64:
            raise MachOError(f"CPU type 0x{cpu & 0xFFFFFFFF:x} is not x86-64")
        if ftype != MH_EXECUTE:
            raise MachOError(f"file type {ftype} is not MH_EXECUTE")

        self.segments: list[Segment] = []
        self.dylibs: list[str] = []
        self.entry_fileoff = None
        dyld_info = chained = fstarts = None
        off = 32
        text_vm = None
        for _ in range(ncmds):
            cmd, cs = struct.unpack_from("<II", d, off)
            if cmd == LC_SEGMENT_64:
                name = d[off + 8:off + 24].rstrip(b"\0").decode()
                vm, vs, fo, fs, maxp, initp, ns, _fl = struct.unpack_from("<QQQQiiII", d, off + 24)
                secs = []
                for k in range(ns):
                    so = off + 72 + 80 * k
                    sname = d[so:so + 16].rstrip(b"\0").decode()
                    saddr, ssize = struct.unpack_from("<QQ", d, so + 32)
                    secs.append((sname, saddr, ssize))
                if name == "__TEXT":
                    text_vm = vm
                self.segments.append(Segment(name, vm, vs, fo, fs, initp, secs))
            elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB,
                         LC_LOAD_UPWARD_DYLIB):
                noff = struct.unpack_from("<I", d, off + 8)[0]
                self.dylibs.append(_cstr(d, off + noff)[0])
            elif cmd == LC_MAIN:
                self.entry_fileoff = struct.unpack_from("<Q", d, off + 8)[0]
            elif cmd == LC_UNIXTHREAD:
                raise MachOError("LC_UNIXTHREAD entry points (pre-10.8 binaries) are not supported")
            elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
                dyld_info = struct.unpack_from("<IIIIIIIIII", d, off + 8)
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                chained = struct.unpack_from("<II", d, off + 8)
            elif cmd == LC_FUNCTION_STARTS:
                fstarts = struct.unpack_from("<II", d, off + 8)
            off += cs
        if text_vm is None:
            raise MachOError("no __TEXT segment")
        if self.entry_fileoff is None:
            raise MachOError("no LC_MAIN entry point")

        # map segments (except __PAGEZERO / __LINKEDIT) relative to __TEXT
        self.image_base = text_vm
        self.mapped = [s for s in self.segments if s.name not in ("__PAGEZERO", "__LINKEDIT")]
        for s in self.mapped:
            if s.vaddr < text_vm:
                raise MachOError(f"segment {s.name} below __TEXT")
        end = max(s.vaddr + s.vsize for s in self.mapped)
        self.size_of_image = end - text_vm
        self.image = bytearray(self.size_of_image)
        for s in self.mapped:
            n = min(s.raw_size, s.vsize)
            self.image[s.vaddr - text_vm:s.vaddr - text_vm + n] = d[s.raw_off:s.raw_off + n]
        # PE-compatible view: sections = mapped segments with RVAs
        self.sections = [Segment(s.name, s.vaddr - text_vm, s.vsize, s.raw_off, s.raw_size, s.prot,
                                 [(n, a - text_vm, z) for n, a, z in s.sections]) for s in self.mapped]
        self.size_of_headers = 0                   # the header lives inside __TEXT
        self.section_alignment = 0x1000
        self.subsystem = 3                         # command-line program (no GUI layer)
        self.dirs = []                             # no PE data directories
        self.dll_characteristics = 0

        tseg = next(s for s in self.segments if s.name == "__TEXT")
        self.entry_rva = self._fileoff_to_rva(self.entry_fileoff)
        del tseg

        self.relocs: list[int] = []
        self.imports: list[tuple[int, str, str]] = []
        if chained is not None:
            self._chained_fixups(chained[0], chained[1])
        elif dyld_info is not None:
            self._dyld_info(*dyld_info)
        self.relocs.sort()
        self.imports.sort()

        self.function_starts = []
        if fstarts is not None:
            p, end = fstarts[0], fstarts[0] + fstarts[1]
            addr = 0                             # offsets are from __TEXT start
            while p < end:
                delta, p = _uleb(d, p)
                if delta == 0:
                    break
                addr += delta
                self.function_starts.append(addr)

    # ---- helpers ---------------------------------------------------------------
    @staticmethod
    def _thin(data):
        if struct.unpack_from(">I", data, 0)[0] != FAT_MAGIC:
            return data
        n = struct.unpack_from(">I", data, 4)[0]
        for i in range(n):
            cpu, _sub, off, size, _al = struct.unpack_from(">iiIII", data, 8 + 20 * i)
            if cpu & 0xFFFFFFFF == CPU_TYPE_X86_64:
                return data[off:off + size]
        raise MachOError("universal file has no x86-64 slice")

    def _fileoff_to_rva(self, fo):
        for s in self.segments:
            if s.raw_off <= fo < s.raw_off + s.raw_size and s.name != "__LINKEDIT":
                return s.vaddr + (fo - s.raw_off) - self.image_base
        raise MachOError(f"file offset 0x{fo:x} is not inside a mapped segment")

    def _seg_rva(self, seg_index, seg_off):
        s = self.segments[seg_index]
        if seg_off >= max(s.vsize, 1):
            raise MachOError(f"fixup outside segment {s.name}")
        return s.vaddr + seg_off - self.image_base

    def _dylib_name(self, ordinal):
        if 1 <= ordinal <= len(self.dylibs):
            return self.dylibs[ordinal - 1]
        raise MachOError(f"unsupported library ordinal {ordinal} (self/main/flat lookup)")

    def _put64(self, rva, v):
        self.image[rva:rva + 8] = struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)

    def _get64(self, rva):
        return struct.unpack_from("<Q", self.image, rva)[0]

    # ---- classic opcodes ----------------------------------------------------------
    def _dyld_info(self, rb_off, rb_size, b_off, b_size, wb_off, wb_size, lb_off, lb_size, _e_off, _e_size):
        d = self.data
        self._rebase_opcodes(d, rb_off, rb_off + rb_size)
        for o, sz, lazy in ((b_off, b_size, False), (lb_off, lb_size, True)):
            if sz:
                self._bind_opcodes(d, o, o + sz, lazy)
        if wb_size:
            # weak binds only coalesce definitions that already exist in the image:
            # nothing to import (a non-weak bind above covers the import itself)
            pass

    def _rebase_opcodes(self, d, p, end):
        seg = None
        off = 0
        typ = 1
        while p < end:
            b = d[p]
            p += 1
            op, imm = b & 0xF0, b & 0x0F
            if op == 0x00:                                   # DONE
                break
            elif op == 0x10:                                 # SET_TYPE_IMM
                typ = imm
                if typ != 1:
                    raise MachOError(f"rebase type {typ} is not REBASE_TYPE_POINTER")
            elif op == 0x20:                                 # SET_SEGMENT_AND_OFFSET_ULEB
                seg = imm
                off, p = _uleb(d, p)
            elif op == 0x30:                                 # ADD_ADDR_ULEB
                v, p = _uleb(d, p)
                off += v
            elif op == 0x40:                                 # ADD_ADDR_IMM_SCALED
                off += imm * 8
            elif op == 0x50:                                 # DO_REBASE_IMM_TIMES
                for _ in range(imm):
                    self.relocs.append(self._seg_rva(seg, off))
                    off += 8
            elif op == 0x60:                                 # DO_REBASE_ULEB_TIMES
                n, p = _uleb(d, p)
                for _ in range(n):
                    self.relocs.append(self._seg_rva(seg, off))
                    off += 8
            elif op == 0x70:                                 # DO_REBASE_ADD_ADDR_ULEB
                self.relocs.append(self._seg_rva(seg, off))
                v, p = _uleb(d, p)
                off += 8 + v
            elif op == 0x80:                                 # DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
                n, p = _uleb(d, p)
                skip, p = _uleb(d, p)
                for _ in range(n):
                    self.relocs.append(self._seg_rva(seg, off))
                    off += 8 + skip
            else:
                raise MachOError(f"unknown rebase opcode 0x{op:x}")

    def _bind_opcodes(self, d, p, end, lazy):
        seg = None
        off = 0
        ordinal = 0
        sym = None
        addend = 0
        while p < end:
            b = d[p]
            p += 1
            op, imm = b & 0xF0, b & 0x0F
            if op == 0x00:                                   # DONE (lazy streams continue)
                if not lazy:
                    break
                continue
            elif op == 0x10:                                 # SET_DYLIB_ORDINAL_IMM
                ordinal = imm
            elif op == 0x20:                                 # SET_DYLIB_ORDINAL_ULEB
                ordinal, p = _uleb(d, p)
            elif op == 0x30:                                 # SET_DYLIB_SPECIAL_IMM
                ordinal = -imm if imm else 0
            elif op == 0x40:                                 # SET_SYMBOL_TRAILING_FLAGS_IMM
                sym, p = _cstr(d, p)
            elif op == 0x50:                                 # SET_TYPE_IMM
                if imm != 1:
                    raise MachOError(f"bind type {imm} is not BIND_TYPE_POINTER")
            elif op == 0x60:                                 # SET_ADDEND_SLEB
                addend, p = _sleb(d, p)
            elif op == 0x70:                                 # SET_SEGMENT_AND_OFFSET_ULEB
                seg = imm
                off, p = _uleb(d, p)
            elif op == 0x80:                                 # ADD_ADDR_ULEB
                v, p = _uleb(d, p)
                off += v
            elif op == 0x90:                                 # DO_BIND
                self._bind(seg, off, ordinal, sym, addend)
                off += 8
            elif op == 0xA0:                                 # DO_BIND_ADD_ADDR_ULEB
                self._bind(seg, off, ordinal, sym, addend)
                v, p = _uleb(d, p)
                off += 8 + v
            elif op == 0xB0:                                 # DO_BIND_ADD_ADDR_IMM_SCALED
                self._bind(seg, off, ordinal, sym, addend)
                off += 8 + imm * 8
            elif op == 0xC0:                                 # DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                n, p = _uleb(d, p)
                skip, p = _uleb(d, p)
                for _ in range(n):
                    self._bind(seg, off, ordinal, sym, addend)
                    off += 8 + skip
            else:
                raise MachOError(f"unsupported bind opcode 0x{op:x}")

    def _bind(self, seg, off, ordinal, sym, addend):
        if addend:
            raise MachOError(f"bind with addend {addend} ({sym}) is not supported")
        rva = self._seg_rva(seg, off)
        if rva in self.relocs:
            self.relocs.remove(rva)       # a lazy pointer is rebased to its stub helper, then bound
        self._put64(rva, 0)
        self.imports.append((rva, self._dylib_name(ordinal), sym))

    # ---- chained fixups -----------------------------------------------------------
    def _chained_fixups(self, off, size):
        d = self.data
        (_ver, starts_off, imports_off, symbols_off, imports_count, imports_fmt,
         _symfmt) = struct.unpack_from("<IIIIIII", d, off)
        names = []
        for i in range(imports_count):
            if imports_fmt == 1:                             # DYLD_CHAINED_IMPORT
                v = struct.unpack_from("<I", d, off + imports_off + 4 * i)[0]
                lib, name_off, addend = v & 0xFF, v >> 9, 0
                lib = lib - 256 if lib > 0xF0 else lib
            elif imports_fmt == 2:                           # DYLD_CHAINED_IMPORT_ADDEND
                v, addend = struct.unpack_from("<Ii", d, off + imports_off + 8 * i)
                lib, name_off = v & 0xFF, v >> 9
                lib = lib - 256 if lib > 0xF0 else lib
            elif imports_fmt == 3:                           # DYLD_CHAINED_IMPORT_ADDEND64
                v, addend = struct.unpack_from("<Qq", d, off + imports_off + 16 * i)
                lib, name_off = v & 0xFFFF, (v >> 32) & 0xFFFFFFFF
                lib = lib - 65536 if lib > 0xFFF0 else lib
            else:
                raise MachOError(f"chained import format {imports_fmt}")
            names.append((lib, _cstr(d, off + symbols_off + name_off)[0], addend))

        seg_count = struct.unpack_from("<I", d, off + starts_off)[0]
        for si in range(seg_count):
            so = struct.unpack_from("<I", d, off + starts_off + 4 + 4 * si)[0]
            if so == 0:
                continue
            base = off + starts_off + so
            (_sz, page_size, ptr_fmt, seg_offset, _maxv, page_count) = struct.unpack_from("<IHHQIH", d, base)
            if ptr_fmt not in (2, 6):                        # DYLD_CHAINED_PTR_64 / _64_OFFSET
                raise MachOError(f"chained pointer format {ptr_fmt} is not supported")
            for pi in range(page_count):
                start = struct.unpack_from("<H", d, base + 22 + 2 * pi)[0]
                if start == 0xFFFF:                          # DYLD_CHAINED_PTR_START_NONE
                    continue
                if start & 0x8000:
                    raise MachOError("multi-start chained fixup pages are not supported")
                rva = seg_offset + pi * page_size + start    # segment_offset is from the mach header
                while True:
                    raw = self._get64(rva)
                    nxt = (raw >> 51) & 0xFFF
                    if raw >> 63:                            # bind
                        ordinal = raw & 0xFFFFFF
                        add = (raw >> 24) & 0xFF
                        lib, sym, addend = names[ordinal]
                        if add or addend:
                            raise MachOError(f"chained bind with addend ({sym}) is not supported")
                        self._put64(rva, 0)
                        self.imports.append((rva, self._dylib_name(lib), sym))
                    else:                                    # rebase
                        target = raw & 0xFFFFFFFFF
                        high8 = (raw >> 36) & 0xFF
                        va = (target if ptr_fmt == 2 else self.image_base + target) | (high8 << 56)
                        self._put64(rva, va)
                        self.relocs.append(rva)
                    if nxt == 0:
                        break
                    rva += nxt * 4

    # ---- PE-compatible accessors -----------------------------------------------------
    def u32(self, rva):
        return struct.unpack_from("<I", self.image, rva)[0]

    def u64(self, rva):
        return struct.unpack_from("<Q", self.image, rva)[0]

    def cstr(self, rva):
        return _cstr(self.image, rva)[0]

    def section_of(self, rva):
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + s.vsize:
                return s
        return None


def load_image(path):
    """Open a PE32+ or Mach-O x86-64 executable."""
    with open(path, "rb") as f:
        head = f.read(4)
    if head[:2] == b"MZ":
        from .pe import PE
        return PE(path)
    return MachO(path)
