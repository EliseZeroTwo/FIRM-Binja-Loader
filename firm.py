from binaryninja import *

class Segment:
    name = ""
    address = 0
    size = 0

    def __init__(self, address, size, name):
        self.address = address
        self.size = size
        self.name = name

ARM11_SEGMENTS = [
    Segment(0x00000000, 0x00010000, "BOOTROM"),
    Segment(0x00010000, 0x00010000, "BOOTROM Mirror"),
    Segment(0x10000000, 0x07E00000, "IO"),
    Segment(0x17E00000, 0x00002000, "MPCore Private Region"),
    Segment(0x17E10000, 0x00001000, "N3DS L2C-310 L2 Cache Controller"),
    Segment(0x18000000, 0x00600000, "VRAM"),
    Segment(0x1F000000, 0x00400000, "N3DS Extra WRAM"),
    Segment(0x1FF00000, 0x00080000, "DSP"),
    Segment(0x1FF80000, 0x00080000, "AXI WRAM"),
    Segment(0x20000000, 0x08000000, "FCRAM"),
    Segment(0x28000000, 0x08000000, "N3DS Extra FCRAM"),
    Segment(0xFFFF0000, 0x00010000, "BOOTROM Mirror"),
]

ARM9_SEGMENTS = [
    Segment(0x00000000, 0x08000000, "Instruction TCM"),
    Segment(0x01FF8000, 0x00008000, "Instruction TCM Kernel & Process Access"),
    Segment(0x07FF8000, 0x00008000, "Instruction TCM BOOTROM Access"),
    Segment(0x08000000, 0x00100000, "WRAM"),
    Segment(0x08100000, 0x00080000, "N3DS Extra WRAM (enabled by CONFIG)"),
    Segment(0x10000000, 0x08000000, "IO Memory"),
    Segment(0x18000000, 0x00600000, "VRAM"),
    Segment(0x1FF00000, 0x00080000, "DSP"),
    Segment(0x1FF80000, 0x00080000, "AXI WRAM"),
    Segment(0x20000000, 0x08000000, "FCRAM"),
    Segment(0x28000000, 0x08000000, "N3DS Extra FCRAM"),
    Segment(0xFFF00000, 0x00004000, "Data TCM"),
    Segment(0xFFFF0000, 0x00010000, "BOOTROM"),
]

class FirmSectionHeader:
    byte_offset = 0
    phys_addr = 0
    byte_len = 0
    copy_method = 0
    sha256_hash = bytearray(b'\x00'*0x20)

    def __init__(self, reader):
        self.byte_offset = reader.read32()
        self.phys_addr = reader.read32()
        self.byte_len = reader.read32()
        self.copy_method = reader.read32()
        self.sha256_hash = reader.read(0x20)



class FirmHeader:
    arm11_entrypoint = 0
    arm9_entrypoint = 0
    sections = []

    def __init__(self, reader):
        reader.seek(0x8)
        self.arm11_entrypoint = reader.read32()
        self.arm9_entrypoint = reader.read32()

        for idx in range(0, 4):
            self.sections.append(FirmSectionHeader(reader))

class FirmView(BinaryView):
    long_name = "3DS FIRM"
    name = "FIRM"
    header = None
    section_header = None
    is_arm11 = False

    def log(self, msg, error=False, warn=False):
        msg = f"[FIRM-Loader] {msg}"
        if error:
            log_error(msg)
        elif warn:
            log_warn(msg)
        else:
            log_info(msg)
    
    def perform_get_address_size(self):
        return 4

    def perform_is_executable(self):
        return True
    
    def perform_get_entry_point(self):
        return self.header.arm11_entrypoint if self.is_arm11 else self.header.arm9_entrypoint

    def __init__(self, data):
        self.raw = data
        self.reader = BinaryReader(data, Endianness.LittleEndian)
        self.writer = BinaryWriter(data, Endianness.LittleEndian)
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)

    @classmethod
    def is_valid_for_data(cls, data):
        return data.read(0, 4) == b'FIRM'

    def init(self):
        self.arch = Architecture["armv7"]
        self.platform = Architecture["armv7"].standalone_platform

        self.header = FirmHeader(self.reader)

        arm9_header = None
        arm11_header = None

        for section in self.header.sections:
            if section.byte_len == 0:
                continue
            
            start = section.phys_addr
            end = start + section.byte_len
            already_set = False

            if start <= self.header.arm9_entrypoint and end > self.header.arm9_entrypoint:
                already_set = True
                arm9_header = section
            
            if start <= self.header.arm11_entrypoint and end > self.header.arm11_entrypoint:
                arm11_header = section
                if already_set:
                    self.log("ARM9 and ARM11 sections overlap", warn=True)
                
        if arm9_header == None and arm11_header == None:
            self.log("FIRM contains no valid section to load", error=True)
        
        if arm9_header != None and arm11_header == None:
            self.log("FIRM contains only an ARM9 section, loading it")
            self.section_header = arm9_header
        elif arm9_header == None and arm11_header != None:
            self.log("FIRM contains only an ARM11 section, loading it")
            self.section_header = arm11_header
        else:
            self.is_arm11 = get_choice_input("Which FIRM?", "Multiple FIRMs found", ["ARM9", "ARM11"]) != 0
            if self.is_arm11:
                self.section_header = arm11_header
            else:
                self.section_header = arm9_header
            self.log(f"Loading {'ARM11' if self.is_arm11 else 'ARM9'} FIRM from file: {hex(self.section_header.byte_offset)} to {hex(self.section_header.phys_addr)} with len {hex(self.section_header.byte_len)}")
                
        self.add_auto_segment(self.section_header.phys_addr, self.section_header.byte_len, self.section_header.byte_offset, self.section_header.byte_len, SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentContainsData)
        entrypoint = self.header.arm11_entrypoint if self.is_arm11 else self.header.arm9_entrypoint
        self.add_entry_point(entrypoint)
        self.add_function(entrypoint, self.platform)
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, entrypoint, "_start"))

        mappings = ARM11_SEGMENTS if self.is_arm11 else ARM9_SEGMENTS
        for mapping in mappings:
            if mapping.address <= self.section_header.phys_addr and (mapping.address + mapping.size) >= (self.section_header.phys_addr + self.section_header.byte_len):
                lower_start = mapping.address
                lower_length = self.section_header.phys_addr - mapping.address

                if lower_length > 0:
                    self.add_user_segment(lower_start, lower_length, 0, 0, SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentContainsData)
                
                upper_start = self.section_header.phys_addr + self.section_header.byte_len
                upper_length = (mapping.address + mapping.size) - upper_start

                if upper_length > 0:
                    self.add_user_segment(upper_start, upper_length, 0, 0, SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentContainsData)
            else:
                self.add_user_segment(mapping.address, mapping.size, 0, 0, SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentContainsData)

            self.add_user_section(mapping.name, mapping.address, mapping.size)
        return True
