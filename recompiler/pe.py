"""Minimal PE32+ (x86-64) parser: headers, sections, imports, base relocations."""
import struct


class PEError(Exception):
    pass


class Section:
    def __init__(self, name, vaddr, vsize, raw_off, raw_size, chars):
        self.name, self.vaddr, self.vsize = name, vaddr, vsize
        self.raw_off, self.raw_size, self.chars = raw_off, raw_size, chars

    @property
    def executable(self):
        return bool(self.chars & 0x20000000)

    def __repr__(self):
        return f"<Section {self.name} rva=0x{self.vaddr:x} size=0x{self.vsize:x}>"


class PE:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if d[:2] != b"MZ":
            raise PEError("not an MZ/PE file")
        pe_off = struct.unpack_from("<I", d, 0x3C)[0]
        if d[pe_off:pe_off + 4] != b"PE\0\0":
            raise PEError("missing PE signature")
        machine, nsec, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", d, pe_off + 4)
        if machine != 0x8664:
            raise PEError(f"unsupported machine 0x{machine:x} (only x86-64 for now)")
        opt = pe_off + 24
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic != 0x20B:
            raise PEError("only PE32+ (64-bit) is supported for now")
        self.entry_rva = struct.unpack_from("<I", d, opt + 16)[0]
        self.image_base = struct.unpack_from("<Q", d, opt + 24)[0]
        self.size_of_image = struct.unpack_from("<I", d, opt + 56)[0]
        self.size_of_headers = struct.unpack_from("<I", d, opt + 60)[0]
        self.section_alignment = struct.unpack_from("<I", d, opt + 32)[0]
        self.dll_characteristics = struct.unpack_from("<H", d, opt + 70)[0]
        self.subsystem = struct.unpack_from("<H", d, opt + 68)[0]
        ndirs = struct.unpack_from("<I", d, opt + 108)[0]
        self.dirs = [struct.unpack_from("<II", d, opt + 112 + 8 * i) for i in range(ndirs)]

        self.sections = []
        sec = opt + opt_size
        for i in range(nsec):
            name, vsize, vaddr, rsize, roff, _, _, _, _, chars = struct.unpack_from(
                "<8sIIIIIIHHI", d, sec + 40 * i)
            self.sections.append(Section(name.rstrip(b"\0").decode(errors="replace"),
                                         vaddr, vsize, roff, rsize, chars))
        self.image = self._map_image()
        self.imports = self._parse_imports()
        self.relocs = self._parse_relocs()

    def _map_image(self):
        img = bytearray(self.size_of_image)
        img[:self.size_of_headers] = self.data[:self.size_of_headers]
        for s in self.sections:
            n = min(s.raw_size, s.vsize or s.raw_size)
            img[s.vaddr:s.vaddr + n] = self.data[s.raw_off:s.raw_off + n]
        return img

    def u32(self, rva):
        return struct.unpack_from("<I", self.image, rva)[0]

    def u64(self, rva):
        return struct.unpack_from("<Q", self.image, rva)[0]

    def cstr(self, rva):
        end = self.image.index(b"\0", rva)
        return self.image[rva:end].decode(errors="replace")

    def _parse_imports(self):
        """Returns list of (iat_slot_rva, dll_name_lower, symbol_name)."""
        out = []
        if len(self.dirs) < 2 or self.dirs[1][0] == 0:
            return out
        desc = self.dirs[1][0]
        while True:
            ilt, _, _, name_rva, iat = struct.unpack_from("<IIIII", self.image, desc)
            if name_rva == 0:
                break
            dll = self.cstr(name_rva).lower()
            lookup = ilt or iat
            i = 0
            while True:
                entry = self.u64(lookup + 8 * i)
                if entry == 0:
                    break
                if entry & (1 << 63):
                    sym = f"#{entry & 0xFFFF}"
                else:
                    sym = self.cstr((entry & 0x7FFFFFFF) + 2)
                out.append((iat + 8 * i, dll, sym))
                i += 1
            desc += 20
        return out

    def _parse_relocs(self):
        """Returns RVAs of 64-bit absolute pointers that need rebasing."""
        out = []
        if len(self.dirs) < 6 or self.dirs[5][0] == 0:
            return out
        pos, end = self.dirs[5][0], self.dirs[5][0] + self.dirs[5][1]
        while pos < end:
            page, size = struct.unpack_from("<II", self.image, pos)
            if size == 0:
                break
            for j in range((size - 8) // 2):
                e = struct.unpack_from("<H", self.image, pos + 8 + 2 * j)[0]
                typ, off = e >> 12, e & 0xFFF
                if typ == 10:  # IMAGE_REL_BASED_DIR64
                    out.append(page + off)
                elif typ != 0:
                    raise PEError(f"unsupported relocation type {typ}")
            pos += size
        return out

    def section_of(self, rva):
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.raw_size):
                return s
        return None
