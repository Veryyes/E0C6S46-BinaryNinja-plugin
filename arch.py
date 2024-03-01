from binaryninja import (
    Architecture,
    Endianness,
    RegisterInfo,
    InstructionInfo,
)

from .disassembler import Disassembler
from .lifter import Lifter

class E0C6S46(Architecture):
    name = "E0C6S46"
    endianness = Endianness.BigEndian

    # 4 bit words
    default_int_size = 1

    # 12 bit instructions
    max_instr_length = 2

    instr_alignment = 1
    
    stack_pointer = "SP"

    #############
    # Registers #
    #############
    regs = {}

    # 4 bits
    regs['A'] = RegisterInfo('A', 1)
    
    # 4 bits
    regs['B'] = RegisterInfo('B', 1)
    
    # 12 bits
    # [. . . .  . . . .  . . . .] IX
    #          [. . . .  . . . .] X
    #          [. . . .]          XH
    #                   [. . . .] XL
    # [. . . .]                   XP  
    regs['IX'] = RegisterInfo('IX', 2)
    # Lower 8 bits of IX
    regs['X'] = RegisterInfo('IX', 1, 0)
    # Upper 4 bits of X
    regs['XH'] = RegisterInfo('X', 1, 0)
    # Lower 4 bits of X
    regs['XL'] = RegisterInfo('X', 1, 0)
    # most significant 4 bits of IX
    regs['XP'] = RegisterInfo('IX', 1 , 1)
    
    # 12 bits
    # [. . . .  . . . .  . . . .] IY
    #          [. . . .  . . . .] Y
    #          [. . . .]          YH
    #                   [. . . .] YL
    # [. . . .]                   YP
    regs['IY'] = RegisterInfo('IY', 2)
    # Lower 8 bits of IY
    regs['Y'] = RegisterInfo('IY', 1, 0)
    # Upper 4 bits of Y
    regs['YH'] = RegisterInfo('Y', 1, 0)
    # Lower 4 bits of Y
    regs['YL'] = RegisterInfo('Y', 1, 0)
    # most significant 4 bits of IY
    regs['YP'] = RegisterInfo('IY', 1 , 1)

    # 8 bits
    regs['SP'] = RegisterInfo('SP', 1)

    # 1 bit
    regs['NBP'] = RegisterInfo('NBP', 1)

    # 4 bits
    regs['NPP'] = RegisterInfo('NPP', 1)

    # 13 bits - PC
    # [X] [X X X X] [X X X X X X X X]
    # PCB    PCP           PCS
    regs['PC'] = RegisterInfo('PC', 2)

    # 4 bit Flag Register
    regs['C'] = RegisterInfo('C', 1)
    regs['Z'] = RegisterInfo('Z', 1)
    regs['D'] = RegisterInfo('D', 1)
    regs['I'] = RegisterInfo('I', 1)


    def __init__(self):
        super().__init__()
        print(f"{self.__class__.__name__} Arch Plugin Loaded")
        self.disassembler = Disassembler()
        self.lifter = Lifter()

    def get_instruction_info(self, data, addr):
        _, branches = self.disassembler.disasm(data, addr)
        instr_info = InstructionInfo(2)
        for branch in branches:
            if branch.target:
                instr_info.add_branch(branch._type, branch.target)
            else:
                instr_info.add_branch(branch._type)

        return instr_info

    def get_instruction_text(self, data, addr):
        tokens, _ = self.disassembler.disasm(data, addr)
        return tokens, 2

    def get_instruction_low_level_il(self, data, addr, il):
        self.lifter.lift(data, addr, il)
        return 2