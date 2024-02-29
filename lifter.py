from binaryninja import (
    LowLevelILLabel,
    LLIL_TEMP,
    ILRegister
)
from .disassembler import Instruction

class Lifter():

    def lift(self, data, addr, il):
        instr = Instruction(data)
        