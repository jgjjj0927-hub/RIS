# language: python, file: embed.py — вшивает promo.mp4 в готовый lab.exe (заменяет .rsrc)
import sys, struct, pefile

RES_ID, RES_TYPE, RES_LANG = 2001, 10, 0x0409

def align(v, a): return (v + a - 1) & ~(a - 1)

def build_rsrc(payload):
    data_off = 88
    type_dir = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1)
    type_ent = struct.pack("<II", RES_TYPE, 0x80000000 | 24)
    name_dir = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1)
    name_ent = struct.pack("<II", RES_ID, 0x80000000 | 48)
    lang_dir = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1)
    lang_ent = struct.pack("<II", RES_LANG, 72)
    data_ent = struct.pack("<IIII", data_off, len(payload), 0, 0)
    blob = type_dir + type_ent + name_dir + name_ent + lang_dir + lang_ent + data_ent
    blob = blob.ljust(data_off, b"\x00") + payload
    return blob.ljust(align(len(blob), 4), b"\x00")

def main(exe, mp4, out):
    video = open(mp4, "rb").read()
    pe = pefile.PE(exe, fast_load=False)

    dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]
    dd[idx].VirtualAddress = 0
    dd[idx].Size = 0
    pe.OPTIONAL_HEADER.NumberOfRvaAndSizes = max(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes, 3)

    last = pe.sections[-1]
    fa = pe.OPTIONAL_HEADER.FileAlignment
    sa = pe.OPTIONAL_HEADER.SectionAlignment
    raw_off = align(last.PointerToRawData + last.SizeOfRawData, fa)
    new_va  = align(last.VirtualAddress + align(last.Misc_VirtualSize, sa), sa)

    blob = build_rsrc(video)

    sec = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
    sec.Name = b".rsrc\x00\x00\x00"
    sec.Misc_VirtualSize = len(blob)
    sec.VirtualAddress = new_va
    sec.SizeOfRawData = align(len(blob), fa)
    sec.PointerToRawData = raw_off
    sec.PointerToRelocations = 0
    sec.PointerToLinenumbers = 0
    sec.NumberOfRelocations = 0
    sec.NumberOfLinenumbers = 0
    sec.Characteristics = 0x40000040

    pe.__structures__.append(sec)
    pe.sections.append(sec)
    dd[idx].VirtualAddress = new_va
    dd[idx].Size = len(blob)
    pe.OPTIONAL_HEADER.SizeOfImage = align(new_va + len(blob), sa)

    data = pe.write()
    if len(data) < raw_off:
        data = data.ljust(raw_off, b"\x00")
    data = data[:raw_off] + blob + data[raw_off + len(blob):]

    with open(out, "wb") as f:
        f.write(data)
    print(f"OK: {out}")
    print(f"  video: {len(video):,} bytes")
    print(f"  .rsrc: {len(blob):,} bytes")
    print(f"  total: {len(data):,} bytes")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: python embed.py lab.exe promo.mp4 lab_packed.exe")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3])
