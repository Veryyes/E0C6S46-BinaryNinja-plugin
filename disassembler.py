from functools import lru_cache


from binaryninja import (
    InstructionTextToken,
    InstructionTextTokenType,
    BranchType
)

@lru_cache()
def dec(binary:str):
    return int(binary, 2)

IMM = 0
ADDR = 1
STR = 2
REG = 3

################################################
# Nomenclature b/c idk what else to call these #
################################################
# B A 9 8 7 6 5 4 3 2 1 0   | Label            #
#---------------------------|------------------#
#[X X X X]                  | UW - Upper Word  #  
#        [X X X X]          | MW - Middle Word #  
#                [X X X X]  | LW - Lower Word  #  
#            [X X]          | ML - Middle Low  #  
#                    [X X]  | LL - Low Low     #
################################################

class Instruction:
    def __init__(self, data:bytes):
        if len(data) == 0:
            raise ValueError("Zero length bytes to decode")
        elif len(data) < 2:
            data = b'\x00' + data
        else:
            data = data[-2:] & (2**12 - 1)

        self.data = data

        self.value = (data[0] << 8) | data[1]
        self.upper_word = data[0] & 15
        self.middle_word = (data[1] & 240) >> 4
        self.lower_word = data[1] & 15
        self.middle_low = data[1] & 48 >> 4
        self.low_low = data[1] & 3

        self.p = self.data[1] & 31
        self.s = (self.middle_word << 4) | self.lower_word
        self.l = self.s
        self.i = self.lower_word

        self.mnemonic = None
        self.op1 = None
        self.op2 = None
        self.cond = None

        # TODO flags
        self.parse()

    def parse(self):
        if self.upper_word == dec('1110') and (self.data[1] >> 1) == dec('010'):
            self.mnemonic = "PSET"
            self.op1 = (self.data[1] & 31, IMM)
            return

        if self.upper_word == 0:
            self.mnemonic = "JP"
            self.op1 = (self.s, ADDR)
            return

        if self.upper_word == dec('10'):
            self.mnemonic = "JP"
            self.op1 = ("C", STR)
            self.op2 = (self.s, ADDR)
            # self.cond = 
            return

        if self.upper_word == dec('11'):
            self.mnemonic = "JP"
            self.op1 = ("NC", STR)
            self.op2 = (self.s, ADDR)
            # self.cond = 
            return

        if self.upper_word == dec('110'):
            self.mnemonic = "JP"
            self.op1 = ("Z", STR)
            self.op2 = (self.s, ADDR)
            # self.cond = 
            return

        if self.upper_word == dec('111'):
            self.mnemonic = "JP"
            self.op1 = ("NZ", STR)
            self.op2 = (self.s, ADDR)
            # self.cond = 
            return

        if self.value == dec('111111101000'):
            self.mnemonic = "JPBA"
            return

        if self.upper_word == dec('0100'):
            self.mnemonic = "CALL"
            return

        if self.upper_word == dec('0101'):
            self.mnemonic = "CALZ"
            return

        if self.value == dec('111111011111'):
            self.mnemonic = "RET"
            return

        if self.value == dec('111111011110'):
            self.mnemonic = "RETS"
            return

class Disassembler:
    def __init__(self):
        # Parse instructions using a tree
        # examine high byte first
        # self.hb_instr = {
        #     14: self.high14
        # }
        pass

    @classmethod
    def parse_operand(op):
        value, _type = op
        if _type == IMM:
            token_type = InstructionTextTokenType.IntegerToken
            value = hex(value)
        elif _type == ADDR:
            token_type = InstructionTextTokenType.AddressDisplayToken
            value = hex(value)
        elif _type == STR:
            token_type = InstructionTextTokenType.TextToken
        elif _type == REG:
            token_type = InstructionTextTokenType.RegisterToken

        return value, token_type

    def disasm(self, data, addr):
        instr = Instruction(data)
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, instr.mnemonic)]
        if self.op1 is not None:
            value, token_type = Disassembler.parse_operand(self.op1)
            tokens.append(InstructionTextToken(token_type, value))
        if self.op2 is not None:
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "))

            value, token_type = Disassembler.parse_operand(self.op2)
            tokens.append(InstructionTextToken(token_type, value))

    # def pset(self, data, addr):


    