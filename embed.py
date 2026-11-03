# language: python, file: embed.py — вшивает promo.mp4 в готовый lab.exe
import sys, struct, pefile

RES_ID, RES_TYPE, RES_LANG = 2001, 10, 0x0409

def align(v, a): return (v + a - 1) & ~(a - 1)

def build_rsrc(payload):
    data_off = 88
    t = struct.pack("<IIHHHH",0,0,0,0,0,1) + struct.pack("<II", RES_TYPE, 0x80000000|24)
    n = struct.pack("<IIHHHH",0,0,0,0,0,1) + struct.pack("<II", RES_ID, 0x80000000|48)
    l = struct.pack("<IIHHHH",0,0,0,0,0,1) + struct.pack("<II", RES_LANG, 72)
    d = struct.pack("<IIII", data_off, len(payload), 0, 0)
    blob = t + n + l + d
    return (blob.ljust(data_off, b"\x00") + payload).ljust(align(len(blob)+len(payload),4), b"\x00")

def main(exe, mp4, out):
    video = open(mp4,"rb").read()
    pe = pefile.PE(exe, fast_load=False)
    dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]
    dd[idx].VirtualAddress = 0; dd[idx].Size = 0
    pe.OPTIONAL_HEADER.NumberOfRvaAndSizes = max(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes, 3)
    last = pe.sections[-1]
    fa = pe.OPTIONAL_HEADER.FileAlignment; sa = pe.OPTIONAL_HEADER.SectionAlignment
    raw_off = align(last.PointerToRawData + last.SizeOfRawData, fa)
    new_va  = align(last.VirtualAddress + align(last.Misc_VirtualSize, sa), sa)
    blob = build_rsrc(video)
    s = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
    s.Name = b".rsrc\x00\x00\x00"
    s.Misc_VirtualSize = len(blob); s.VirtualAddress = new_va
    s.SizeOfRawData = align(len(blob), fa); s.PointerToRawData = raw_off
    s.PointerToRelocations = 0; s.PointerToLinenumbers = 0
    s.NumberOfRelocations = 0; s.NumberOfLinenumbers = 0
    s.Characteristics = 0x40000040
    pe.__structures__.append(s); pe.sections.append(s)
    dd[idx].VirtualAddress = new_va; dd[idx].Size = len(blob)
    pe.OPTIONAL_HEADER.SizeOfImage = align(new_va + len(blob), sa)
    data = pe.write()
    if len(data) < raw_off: data = data.ljust(raw_off, b"\x00")
    data = data[:raw_off] + blob + data[raw_off+len(blob):]
    open(out,"wb").write(data)
    print(f"OK {out}: video {len(video)}B, total {len(data)}B")

if __name__ == "__main__":
    if len(sys.argv)!=4: sys.exit("usage: python embed.py lab.exe promo.mp4 lab_packed.exe")
    main(sys.argv[1], sys.argv[2], sys.argv[3])
