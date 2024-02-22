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
REG_DEREF = 4

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
    r = [
        ('A', REG),
        ('B', REG),
        ('IX', REG_DEREF),
        ('IY', REG_DEREF)
    ]

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
        # BRANCH INSTRUCTIONS
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

        if self.upper_word == dec('0001'):
            self.mnemonic = "RETD"
            self.op1 = ((self.middle_word << 4) | self.lower_word, IMM)
            return

        # SYSTEM CONTROL
        if self.value == dec('111111111011'):
            self.mnemonic = "NOP5"
            return

        if self.value == dec('111111111111'):
            self.mnemonic = "NOP7"
            return

        if self.value == dec('111111111000'):
            self.mnemonic = "HALT"
            return

        # INDEX OPERATIONS

        # INC
        if self.value == dec('111011100000'):
            self.mnemonic = "INC"
            self.op1 = ("X", REG)
            return

        if self.value == dec('111011110000'):
            self.mnemonic = "INC"
            self.op1 = ("Y", REG)
            return

        # LD
        if self.upper_word == dec('1011'):
            self.mnemonic = "LD"
            self.op1 = ("X", REG)
            self.op2 = (self.s, IMM)

        if self.upper_word == dec('1000'):
            self.mnemonic = "LD"
            self.op1 = ("Y", REG)
            self.op2 = (self.s, IMM)

        if self.upper_word == dec('1110'):
            low_high = (self.lower_word >> 2) & 3
            if self.middle_word == dec('1000'):
                self.mnemonic = "LD"
                if low_high == dec('00'):
                    self.op1 = ("XP", REG)
                    self.op2 = self.r[low_high]
                    return
                elif low_high == dec('01'):
                    self.op1 = ("XH", REG)
                    self.op2 = self.r[low_high]
                    return
                elif low_high == dec('10'):
                    self.op1 = ("XL", REG)
                    self.op2 = self.r[low_high]
                    return
            elif self.middle_word == dec('1001'):
                self.mnemonic = "LD"
                if low_high == dec('00'):
                    self.op1 = ("YP", REG)
                    self.op2 = self.r[low_high]
                    return
                elif low_high == dec('01'):
                    self.op1 = ("YH", REG)
                    self.op2 = self.r[low_high]
                    return
                elif low_high == dec('10'):
                    self.op1 = ("YL", REG)
                    self.op2 = self.r[low_high]
                    return
            elif self.middle_word == dec('1010'):
                self.mnemonic = "LD"
                if low_high == dec('00'):
                    self.op1 = self.r[low_high]
                    self.op2 = ("XP", REG)
                    return
                elif low_high == dec('01'):
                    self.op1 = self.r[low_high]
                    self.op2 = ("XH", REG)
                    return
                elif low_high == dec('10'):
                    self.op1 = self.r[low_high]
                    self.op2 = ("XL", REG)
                    return
            elif self.middle_word == dec('1011'):
                self.mnemonic = "LD"
                if low_high == dec('00'):
                    self.op1 = self.r[low_high]
                    self.op2 = ("YP", REG)
                    return
                elif low_high == dec('01'):
                    self.op1 = self.r[low_high]
                    self.op2 = ("YH", REG)
                    return
                elif low_high == dec('10'):
                    self.op1 = self.r[low_high]
                    self.op2 = ("YL", REG)
                    return
        
        
        if self.upper_word == dec('1010'):
            # ADC
            if self.middle_word == dec('0000'):
                self.mnemonic = "ADC"
                self.op1 = ("XH", REG)
                self.op2 = (self.lower_word, IMM)
                return
            elif self.middle_word == dec('0001'):
                self.mnemonic = "ADC"
                self.op1 = ("XL", REG)
                self.op2 = (self.lower_word, IMM)
                return
            elif self.middle_word == dec('0010'):
                self.mnemonic = "ADC"
                self.op1 = ("YH", REG)
                self.op2 = (self.lower_word, IMM)
                return
            elif self.middle_word == dec('0011'):
                self.mnemonic = "ADC"
                self.op1 = ("YL", REG)
                self.op2 = (self.lower_word, IMM)
                return

            # CP
            if self.middle_word == dec('0100'):
                self.mnemonic = "CP"
                self.op1 = ("XH", REG)
                self.op2 = (self.lower_word, IMM)
                return
            elif self.middle_word == dec('0101'):
                self.mnemonic = "CP"
                self.op1 = ("XH", REG)
                self.op2 = (self.lower_word, IMM)
                return
            elif self.middle_word == dec('0110'):
                self.mnemonic = "CP"
                self.op1 = ("XH", REG)
                self.op2 = (self.lower_word, IMM)
                return
            elif self.middle_word == dec('0111'):
                self.mnemonic = "CP"
                self.op1 = ("XH", REG)
                self.op2 = (self.lower_word, IMM)
                return

        # LD
        if self.upper_word == dec('1110'):
            if (self.middle_word >> 2) & 3 == dec('00'):
                self.mnemonic = "LD"
                self.op1 = self.r[self.middle_low]
                self.op2 = (self.lower_word, IMM)
                return
            elif self.middle_word == dec('1111'):
                self.mnemonic = "LD"
                self.op1 = self.r[(self.lower_word >> 2) & 3]
                self.op2 = self.r[self.lower_word & 3]
                return
        if self.upper_word == dec('1111'):
            if self.middle_word == dec('1010'):
                self.mnemonic = "LD"
                self.op1 = ("A", REG)
                self.op2 = (self.lower_word, ADDR)
                return
            elif self.middle_word == dec('1011'):
                self.mnemonic = "LD"
                self.op1 = ("B", REG)
                self.op2 = (self.lower_word, ADDR)
                return
            elif self.middle_word == dec('1000'):
                self.mnemonic = "LD"
                self.op1 = (self.lower_word, ADDR)
                self.op2 = ("A", REG)
                return
            elif self.middle_word == dec('1001'):
                self.mnemonic = "LD"
                self.op1 = (self.lower_word, ADDR)
                self.op2 = ("B", REG)
                return 

        if self.upper_word == dec('1110'):
            # LDPX
            if self.middle_word == dec('0110'):
                self.mnemonic = "LDPX"
                self.op1 = ("IX", REG_DEREF)
                self.op2 = (self.lower_word, IMM)
                return
            elif self.middle_word == dec('1110'):
                self.mnemonic = "LDPX"
                self.op1 = self.r[(self.lower_word >> 2) & 3]
                self.op2 = self.r[self.lower_word & 3]
                return
            # LDPY
            elif self.middle_word == dec('0111'):
                self.mnemonic = "LDPY"
                self.op1 = ("IY", REG_DEREF)
                self.op2 = (self.lower_word, IMM)
                return
            elif self.middle_word == dec('1111'):
                self.mnemonic = "LDPY"
                self.op1 = self.r[(self.lower_word >> 2) & 3]
                self.op2 = self.r[self.lower_word & 3]
                return



class Disassembler:
    def __init__(self):
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


    