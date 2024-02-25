from binaryninja import (
    Architecture,
    BinaryView,
    Endianness,
    SegmentFlag,
    SectionSemantics
)
class View(BinaryView):
    name = "E0C6S46"
    long_name = "E0C6S46 Loader"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, data):
        return True

    def perform_get_default_endianness(self):
        return Endianness.BigEndian

    def init(self):
        self.platform = Architecture["E0C6S46"].standalone_platform
        self.arch = Architecture["E0C6S46"]
        
        self.add_auto_segment(0, 0x3000, 0, 0x3000,
            SegmentFlag.SegmentReadable |
            SegmentFlag.SegmentContainsCode | 
            SegmentFlag.SegmentExecutable
        )
        return True