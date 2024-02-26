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
            data = data[-2:]

        self.data = data

        # "Macros" to make parsing easier
        self.value = (data[0] << 8) | data[1]
        self.upper_word = data[0] & 15
        self.middle_word = (data[1] & 240) >> 4
        self.lower_word = data[1] & 15
        self.middle_low = data[1] & 48 >> 4
        self.low_low = data[1] & 3

        self.p = data[1] & 31
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
                if low_high == dec('01'):
                    self.op1 = ("XH", REG)
                    self.op2 = self.r[low_high]
                    return
                if low_high == dec('10'):
                    self.op1 = ("XL", REG)
                    self.op2 = self.r[low_high]
                    return

            if self.middle_word == dec('1001'):
                self.mnemonic = "LD"
                if low_high == dec('00'):
                    self.op1 = ("YP", REG)
                    self.op2 = self.r[low_high]
                    return
                if low_high == dec('01'):
                    self.op1 = ("YH", REG)
                    self.op2 = self.r[low_high]
                    return
                if low_high == dec('10'):
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

            if self.middle_word == dec('1000'):
                if self.lower_word >> 2 == 3:
                    self.mnemonic = "RRC"
                    self.op1 = self.r[self.low_low]
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
            if self.middle_word == dec('1110'):
                self.mnemonic = "LDPX"
                self.op1 = self.r[(self.lower_word >> 2) & 3]
                self.op2 = self.r[self.lower_word & 3]
                return
            # LDPY
            if self.middle_word == dec('0111'):
                self.mnemonic = "LDPY"
                self.op1 = ("IY", REG_DEREF)
                self.op2 = (self.lower_word, IMM)
                return
            elif self.middle_word == dec('1111'):
                self.mnemonic = "LDPY"
                self.op1 = self.r[(self.lower_word >> 2) & 3]
                self.op2 = self.r[self.lower_word & 3]
                return

        if self.upper_word == dec('1001'):
            self.mnemonic = "LBPX"
            self.op1 = ("IX", REG_DEREF)
            self.op2 = ((self.middle_word << 4) | self.lower_word, IMM)
            return

        if self.upper_word == dec('1111'):
            if self.middle_word == dec('0100'):
                if self.lower_word == dec('0001'):
                    self.mnemonic = "SCF"
                    return
                if self.lower_word == dec('0010'):
                    self.mnemonic = "SZF"
                    return
                if self.lower_word == dec('0100'):
                    self.mnemonic = "SDF"
                    return
                if self.lower_word == dec('1000'):
                    self.mnemonic = "EI"
                    return
            if self.middle_word == dec('0101'):
                if self.lower_word == dec("1110"):
                    self.mnemonic = "RCF"
                    return
                if self.lower_word == dec('1101'):
                    self.mnemonic = "RZF"
                    return
                if self.lower_word == dec('1011'):
                    self.mnemonic = "RDF"
                    return
                if self.lower_word == dec('0111'):
                    self.mnemonic = "DI"
                    return

            if self.middle_word == dec('0100'):
                self.mnemonic = "SET"
                self.op1 = ("F", REG)
                self.op2 = (self.lower_word, IMM)
                return
            if self.middle_word == dec('0101'):
                self.mnemonic = "RST"
                self.op1 = ("F", REG)
                self.op2 = (self.lower_word, IMM)
                return

            # Stack Operations
            if self.middle_word == dec('1101') and self.lower_word == dec('1011'):
                self.mnemonic = "INC"
                self.op1 = ("SP", REG)
                return
            
            if self.middle_word == dec('1100'):
                if self.lower_word == dec('1011'):
                    self.mnemonic = "DEC"
                    self.op1 = ("SP", REG)
                    return

                if self.lower_word >> 2 == dec('00'):
                    self.mnemonic = "PUSH"
                    self.op1 = self.r[self.low_low & 3]
                    return
                if self.lower_word == dec('0100'):
                    self.mnemonic = "PUSH"
                    self.op1 = ("XP", REG)
                    return
                if self.lower_word == dec('0101'):
                    self.mnemonic = "PUSH"
                    self.op1 = ("XH", REG)
                    return
                if self.lower_word == dec('0110'):
                    self.mnemonic = "PUSH"
                    self.op1 = ("XL", REG)
                    return
                if self.lower_word == dec('0111'):
                    self.mnemonic = "PUSH"
                    self.op1 = ("YP", REG)
                    return
                if self.lower_word == dec('1000'):
                    self.mnemonic = "PUSH"
                    self.op1 = ("YH", REG)
                    return
                if self.lower_word == dec('1001'):
                    self.mnemonic = "PUSH"
                    self.op1 = ("YL", REG)
                    return
                if self.lower_word == dec('1010'):
                    self.mnemonic = "PUSH"
                    self.op1 = ("F", REG)
                    return
            
            if self.middle_word == dec('1101'):
                if self.lower_word >> 2 == dec('00'):
                    self.mnemonic = "POP"
                    self.op1 = self.r[self.lower_word & 3]
                    return
                if self.lower_word == dec('0100'):
                    self.mnemonic = "POP"
                    self.op1 = ("XP", REG)
                    return
                if self.lower_word == dec('0101'):
                    self.mnemonic = "POP"
                    self.op1 = ("XH", REG)
                    return
                if self.lower_word == dec('0110'):
                    self.mnemonic = "POP"
                    self.op1 = ("XL", REG)
                    return
                if self.lower_word == dec('0111'):
                    self.mnemonic = "POP"
                    self.op1 = ("YP", REG)
                    return
                if self.lower_word == dec('1000'):
                    self.mnemonic = "POP"
                    self.op1 = ("YH", REG)
                    return
                if self.lower_word == dec('1001'):
                    self.mnemonic = "POP"
                    self.op1 = ("YL", REG)
                    return
                if self.lower_word == dec('1010'):
                    self.mnemonic = "POP"
                    self.op1 = ("F", REG)
                    return
            
            if self.middle_word == dec('1110'):
                if (self.lower_word >> 2) == 0:
                    self.mnemonic = "LD"
                    self.op1 = ("SPH", REG)
                    self.op2 = self.r[self.low_low]
                    return
                if (self.lower_word >> 2) == 1:
                    self.mnemonic = "LD"
                    self.op1 = self.r[self.low_low]
                    self.op2 = ("SPH", REG)
                    return

            if self.middle_word == dec('1111'):
                if (self.lower_word >> 2) == 0:
                    self.mnemonic = "LD"
                    self.op1 = ("SPL", REG)
                    self.op2 = self.r[self.low_low]
                    return
                if (self.lower_word >> 2) == 1:
                    self.mnemonic = "LD"
                    self.op1 = self.r[self.low_low]
                    self.op2 = ("SPL", REG)
                    return
            if self.middle_word == dec('0000'):
                self.mnemonic = "CP"
                self.op1 = self.r[self.lower_word >> 2]
                self.op2 = self.r[self.low_low]
                return
            if self.middle_word == dec('0001'):
                self.mnemonic = "FAN"
                self.op1 = self.r[self.lower_word >> 2]
                self.op2 = self.r[self.low_low]
                return
            if self.middle_word == dec('0110'):
                self.mnemonic = "INC"
                self.op1 = (self.lower_word, ADDR)
                return
            if self.middle_word == dec('0111'):
                self.mnemonic = "DEC"
                self.op1 = (self.lower_word, ADDR)
                return
            if self.middle_word == dec('0010'):
                if self.lower_word >> 2 == 2:
                    self.mnemonic = "ACPX"
                    self.op1 = ("IX", REG_DEREF)
                    self.op2 = self.r[self.low_low]
                    return
                if self.lower_word >> 2 == 3:
                    self.mnemonic = "ACPY"
                    self.op1 = ("IY", REG_DEREF)
                    self.op2 = self.r[self.low_low]
                    return
            if self.middle_word == dec('0011'):
                if self.lower_word >> 2 == 2:
                    self.mnemonic = "SCPX"
                    self.op1 = ("IX", REG_DEREF)
                    self.op2 = self.r[self.low_low]
                    return
                if self.lower_word >> 2 == 3:
                    self.mnemonic = "SCPY"
                    self.op1 = ("IY", REG_DEREF)
                    self.op2 = self.r[self.low_low]
                    return

        # Arithmetic
        if self.upper_word == dec('1100'):
            if (self.middle_word >> 2) == 0:
                self.mnemonic = "ADD"
                self.op1 = self.r[self.middle_low]
                self.op2 = (self.lower_word, IMM)
                return

            if (self.middle_word >> 2) == 1:
                self.mnemonic = "ADC"
                self.op1 = self.r[self.middle_low]
                self.op2 = (self.lower_word, IMM)
                return

            if (self.middle_word >> 2) == 2:
                self.mnemonic = "AND"
                self.op1 = self.r[self.middle_low]
                self.op2 = (self.lower_word, IMM)
                return

            if (self.middle_word >> 2) == 3:
                self.mnemonic = "OR" 
                self.op1 = self.r[self.middle_low]
                self.op2 = (self.lower_word, IMM)
                return

        if self.upper_word == dec('1010'):
            if self.middle_word == dec('1000'):
                self.mnemonic = "ADD"
                self.op1 = self.r[self.lower_word >> 2]
                self.op2 = self.r[self.low_low]
                return

            if self.middle_word == dec('1001'):
                self.mnemonic = "ADC"
                self.op1 = self.r[self.lower_word >> 2]
                self.op2 = self.r[self.low_low]
                return

            if self.middle_word == dec('1010'):
                self.mnemonic = "SUB"
                self.op1 = self.r[self.lower_word >> 2]
                self.op2 = self.r[self.low_low]
                return

            if self.middle_word == dec('1011'):
                self.mnemonic = "SBC"
                self.op1 = self.r[self.lower_word >> 2]
                self.op2 = self.r[self.low_low]
                return

            if self.middle_word == dec('1100'):
                self.mnemonic = "AND"
                self.op1 = self.r[self.lower_word >> 2]
                self.op2 = self.r[self.low_low]
                return
            
            if self.middle_word == dec('1101'):
                self.mnemonic = "OR"
                self.op1 = self.r[self.lower_word >> 2]
                self.op2 = self.r[self.low_low]
                return

            if self.middle_word == dec('1110'):
                self.mnemonic = "XOR"
                self.op1 = self.r[self.lower_word >> 2]
                self.op2 = self.r[self.low_low]
                return
            
            if self.middle_word == dec("1111"):
                self.mnemonic = "RLC"
                self.op1 = self.r[self.low_low]
                return

            
        if self.upper_word == dec('1101'):
            if self.middle_word >> 2 == 1:
                self.mnemonic = "SBC"
                self.op1 = self.r[self.middle_low]
                self.op2 = (self.lower_word, IMM)
                return
            if self.middle_word >> 2 == 0:
                self.mnemonic = "XOR"
                self.op1 = self.r[self.middle_low]
                self.op2 = (self.lower_word, IMM)
                return
            if self.middle_word >> 2 == 3:
                self.mnemonic = "CP"
                self.op1 = self.r[self.middle_low]
                self.op2 = (self.lower_word, IMM)
                return
            if self.middle_word >> 2 == 2:
                self.mnemonic = "FAN"
                self.op1 = self.r[self.middle_low]
                self.op2 = (self.lower_word, IMM)
                return
            if self.middle_word >> 2 == 0 and self.lower_word == dec('1111'):
                self.mnemonic = "NOT"
                self.op1 = self.r[self.middle_word & 3]
                return

        self.mnemonic = "UNKNOWN"

# IMM = 0
# ADDR = 1
# STR = 2
# REG = 3
# REG_DEREF = 4

class Disassembler:
    def __init__(self):
        pass

    @classmethod
    def parse_operand(cls, op):
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
        elif _type == REG_DEREF:
            token_type = InstructionTextTokenType.RegisterToken

        return value, token_type

    def disasm(self, data, addr):
        instr = Instruction(data)
        # print(instr.mnemonic)
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, instr.mnemonic)]
        if instr.op1 is not None:
            value, token_type = Disassembler.parse_operand(instr.op1)
            tokens.append(InstructionTextToken(token_type, value))
        if instr.op2 is not None:
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "))

            value, token_type = Disassembler.parse_operand(instr.op2)
            tokens.append(InstructionTextToken(token_type, value))

        return tokens, []
    