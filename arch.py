from binaryninja import (
    Architecture,
    Endianness,
    RegisterInfo,
    IntrinsicInfo,
    Type,
    InstructionInfo
)

from .disassembler import Disassembler

# Registers #
#
# 

class E0C6S46(Architecture):
    name = "E0C6S46"
    endianness = Endianness.BigEndian

    # 4 bit words
    default_int_size = 1

    # 12 bit instructions
    max_instr_size = 2

    instr_alignment = 1
    stack_pointer = "PC"

    #############
    # Registers #
    #############
    regs = {}

    # 4 bits
    regs['A'] = RegisterInfo('A', 1)
    
    # 4 bits
    regs['B'] = RegisterInfo('B', 1)
    
    # 12 bits
    regs['IX'] = RegisterInfo('IX', 2)
    
    # 12 bits
    regs['IY'] = RegisterInfo('IY', 2)

    # 8 bits
    regs['SP'] = RegisterInfo('SP', 1)

    # 1 bit
    regs['NBP'] = RegisterInfo('NBP', 1)

    # 4 bits
    regs['NPP'] = RegisterInfo('NPP', 1)

    # 1 bit
    regs['PCB'] = RegisterInfo('PCB', 1)

    # 4 bits
    regs['PCP'] = RegisterInfo('PCP', 1)

    # 8 bits
    regs['PCS'] = RegisterInfo('PCS', 1)

    # 4 bits
    regs['F'] = RegisterInfo('F', 1)

    def __init__(self):
        super().__init__()
        print(f"{self.__class__.__name__} Arch Plugin Loaded")
        self.disassembler = Disassembler()

    def get_instruction_info(self, data, addr):
        # print(type(data))
        pass