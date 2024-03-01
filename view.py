from binaryninja import (
    Architecture,
    BinaryView,
    Endianness,
    SegmentFlag,
    BinaryReader
)

from .disassembler import Instruction, psets

class View(BinaryView):
    name = "E0C6S46"
    long_name = "E0C6S46 Loader"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, data):
        return data.file.filename.endswith('.b')

    def perform_get_default_endianness(self):
        return Endianness.BigEndian

    def perform_is_executable(self):
        return True

    def perform_get_address_size(self):
        return 2

    def find_psets(self):
        br = BinaryReader(self, Endianness.BigEndian)
        addr = 0
        instr_data = br.read(2)

        while(instr_data is not None):
            instr = Instruction(instr_data, addr)
            if instr.mnemonic == "PSET":
                # log.log_info(f"{hex(instr.addr)}: {instr.mnemonic}")
                psets.add(instr.addr, instr)
            addr += 2
            instr_data = br.read(2)

    def init(self):
        self.platform = Architecture["E0C6S46"].standalone_platform
        self.arch = Architecture["E0C6S46"]
        
        self.add_auto_segment(0, 0x3000, 0, 0x3000,
            SegmentFlag.SegmentReadable |
            SegmentFlag.SegmentContainsCode | 
            SegmentFlag.SegmentExecutable
        )

        self.add_entry_point(0x100 * 2)

        self.find_psets()

        return True