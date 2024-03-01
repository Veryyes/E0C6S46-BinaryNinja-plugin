from typing import Dict
from functools import lru_cache
from dataclasses import dataclass
import bisect
from collections import defaultdict

from binaryninja import (
    InstructionTextToken,
    InstructionTextTokenType,
    BranchType, 
    LowLevelILLabel
)

# TODO replace all calls of this 
# i am dumb
@lru_cache()
def dec(binary:str):
    return int(binary, 2)

@dataclass
class BranchInfo:
    _type:BranchType
    target:int = None

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

    def __init__(self, data:bytes, addr:int, il=None):
        if len(data) == 0:
            raise ValueError("Zero length bytes to decode")
        elif len(data) < 2:
            data = b'\x00' + data
        else:
            data = data[-2:]

        self.data = data
        self.addr = addr

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
        self.branches = []
        self.comment = None

        self.il = il

        self.parse()

    def parse(self):
        il = self.il
        if il:
            # convenient consts 
            twelve = il.const(1, 12)
            eight = il.const(1, 8)
            four = il.const(1, 4)
            one = il.const(1, 1)
            zero = il.const(1, 0)

        # BRANCH INSTRUCTIONS
        if self.upper_word == dec('1110') and (self.middle_word >> 1) == dec('010'):
            self.mnemonic = "PSET"
            self.op1 = (self.data[1] & 31, IMM)

            if il:
                op1 = il.const(1, self.op1[0])

                # NBP = 5th msb of op1
                bank = il.arith_shift_right(1, op1, il.const(1, 4))
                il.append(il.set_reg(1, "NBP", bank))

                # NPP = least sig nibble of op1
                mask = il.const(1, 15)
                page = il.and_expr(1, op1, mask)
                il.append(il.set_reg(1, "NPP", page))

            return

        if self.upper_word == 0:
            self.mnemonic = "JP"
            self.op1 = (self.s, ADDR)
                       
            pset = psets.get(self.addr)
            target_addr = 2 * ((pset.op1[0] << 8) | self.s)
            self.branches.append(BranchInfo(_type=BranchType.UnconditionalBranch, target=target_addr))

            if il:
                nbp = il.reg(1, "NBP")
                npp = il.reg(1, "NPP")
                step = il.const(1, self.s)

                nbp = il.shift_left(2, nbp, twelve)
                npp = il.shift_left(2, npp, eight)

                target = il.or_expr(2, nbp, npp)
                target = il.or_expr(2, target, step)

                # Double address
                target = il.shift_left(2, target, one)
                il.append(il.jump(target))

            return

        if self.upper_word == dec('10'):
            self.mnemonic = "JP"
            self.op1 = ("C", STR)
            self.op2 = (self.s, ADDR)

            pset = psets.get(self.addr)
            target_addr = 2 * ((pset.op1[0] << 8) | self.s)
            self.branches.append(BranchInfo(_type=BranchType.TrueBranch, target=target_addr))
            self.branches.append(BranchInfo(_type=BranchType.FalseBranch, target=self.addr+2))

            if il:
                c = il.reg(1, "C")
                nbp = il.reg(1, "NBP")
                npp = il.reg(1, "NPP")
                step = il.const(1, self.s)

                nbp = il.shift_left(2, nbp, twelve)
                npp = il.shift_left(2, npp, eight)

                target = il.or_expr(2, nbp, npp)
                target = il.or_expr(2, target, step)

                # Double address
                target = il.shift_left(2, target, one)
                il.append(il.jump(target))

                cond = il.compare_equal(1, one, c)
                t = LowLevelILLabel()
                f = LowLevelILLabel()
                il.append(il.if_expr(cond, t, f))
                il.mark_label(t)
                il.append(il.jump(target))
                il.mark_label(f)

            return

        if self.upper_word == dec('11'):
            self.mnemonic = "JP"
            self.op1 = ("NC", STR)
            self.op2 = (self.s, ADDR)

            pset = psets.get(self.addr)
            target_addr = 2 * ((pset.op1[0] << 8) | self.s)
            self.branches.append(BranchInfo(_type=BranchType.TrueBranch, target=target_addr))
            self.branches.append(BranchInfo(_type=BranchType.FalseBranch, target=self.addr+2))

            if il:
                c = il.reg(1, "C")
                nbp = il.reg(1, "NBP")
                npp = il.reg(1, "NPP")
                step = il.const(1, self.s)

                nbp = il.shift_left(2, nbp, twelve)
                npp = il.shift_left(2, npp, eight)

                target = il.or_expr(2, nbp, npp)
                target = il.or_expr(2, target, step)

                # Double address
                target = il.shift_left(2, target, one)
                il.append(il.jump(target))

                cond = il.compare_equal(1, zero, c)
                t = LowLevelILLabel()
                f = LowLevelILLabel()
                il.append(il.if_expr(cond, t, f))
                il.mark_label(t)
                il.append(il.jump(target))
                il.mark_label(f)

            return

        if self.upper_word == dec('110'):
            self.mnemonic = "JP"
            self.op1 = ("Z", STR)
            self.op2 = (self.s, ADDR)

            pset = psets.get(self.addr)
            target_addr = 2 * ((pset.op1[0] << 8) | self.s)
            self.branches.append(BranchInfo(_type=BranchType.TrueBranch, target=target_addr))
            self.branches.append(BranchInfo(_type=BranchType.FalseBranch, target=self.addr+2))
            
            if il:
                z = il.reg(1, "Z")
                nbp = il.reg(1, "NBP")
                npp = il.reg(1, "NPP")
                step = il.const(1, self.s)

                nbp = il.shift_left(2, nbp, twelve)
                npp = il.shift_left(2, npp, eight)

                target = il.or_expr(2, nbp, npp)
                target = il.or_expr(2, target, step)

                # Double address
                target = il.shift_left(2, target, one)
                il.append(il.jump(target))

                cond = il.compare_equal(1, one, z)
                t = LowLevelILLabel()
                f = LowLevelILLabel()
                il.append(il.if_expr(cond, t, f))
                il.mark_label(t)
                il.append(il.jump(target))
                il.mark_label(f)
            
            return

        if self.upper_word == dec('111'):
            self.mnemonic = "JP"
            self.op1 = ("NZ", STR)
            self.op2 = (self.s, ADDR)

            pset = psets.get(self.addr)
            target_addr = 2 * ((pset.op1[0] << 8) | self.s)
            self.branches.append(BranchInfo(_type=BranchType.TrueBranch, target=target_addr))
            self.branches.append(BranchInfo(_type=BranchType.FalseBranch, target=self.addr+2))

            if il:
                z = il.reg(1, "Z")
                nbp = il.reg(1, "NBP")
                npp = il.reg(1, "NPP")
                step = il.const(1, self.s)

                nbp = il.shift_left(2, nbp, twelve)
                npp = il.shift_left(2, npp, eight)

                target = il.or_expr(2, nbp, npp)
                target = il.or_expr(2, target, step)

                # Double address
                target = il.shift_left(2, target, one)
                il.append(il.jump(target))

                cond = il.compare_equal(1, zero, z)
                t = LowLevelILLabel()
                f = LowLevelILLabel()
                il.append(il.if_expr(cond, t, f))
                il.mark_label(t)
                il.append(il.jump(target))
                il.mark_label(f)
            
            return

        if self.value == dec('111111101000'):
            self.mnemonic = "JPBA"
            self.branches.append(BranchInfo(_type=BranchType.IndirectBranch))
            
            if il:
                pset = psets.get(self.addr)
                a = il.reg(1, "A")
                b = il.reg(1, "B")
                
                # Jump to NBP << 12 | NPP << 8 | B << 4 | A
                nbp = il.reg(1, "NBP")
                npp = il.reg(1, "NPP")
                step = il.const(1, self.s)

                nbp = il.shift_left(2, nbp, twelve)
                npp = il.shift_left(2, npp, eight)

                target = il.or_expr(2, nbp, npp)
                target = il.or_expr(2, target, il.shift_left(1, b, four))
                target = il.or_expr(2, target, a)
                
                # Double address
                target = il.shift_left(2, target, one)
                il.append(il.jump(target))


            return

        if self.upper_word == dec('0100'):
            self.mnemonic = "CALL"
            self.op1 = (self.s, ADDR)
            
            
            pset = psets.get(self.addr)

            # NBP not used
            # Bank of Current PC | Page set by PSET | op1
            target_addr = self.addr & (1 << 13)
            target_addr |= (pset.op1[0] & 15) << 8
            target_addr |= self.s
            target_addr = 2 * target_addr
            
            self.branches.append(BranchInfo(_type=BranchType.CallDestination, target=target_addr))
            return

        if self.upper_word == dec('0101'):
            self.mnemonic = "CALZ"
            self.op1 = (self.s, ADDR)

            # Bank of Current PC | Page 0 | op1
            target_addr = self.addr & (1 << 13)
            target_addr |= self.s
            target_addr = 2 * target_addr
            self.branches.append(BranchInfo(_type=BranchType.CallDestination, target=target_addr))
            return

        if self.value == dec('111111011111'):
            self.mnemonic = "RET"
            self.branches.append(BranchInfo(_type=BranchType.FunctionReturn))
            return

        if self.value == dec('111111011110'):
            self.mnemonic = "RETS"
            # i.e. the PC it should return to is Return Address + 2
            self.comment = "Skips over the next instruction after returning"
            self.branches.append(BranchInfo(_type=BranchType.FunctionReturn))
            return

        if self.upper_word == dec('0001'):
            self.mnemonic = "RETD"
            self.op1 = ((self.middle_word << 4) | self.lower_word, IMM)
            self.branches.append(BranchInfo(_type=BranchType.FunctionReturn))
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
            return

        if self.upper_word == dec('1000'):
            self.mnemonic = "LD"
            self.op1 = ("Y", REG)
            self.op2 = (self.s, IMM)
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

            if self.middle_word == dec('0101'):
                self.mnemonic = "CP"
                self.op1 = ("XH", REG)
                self.op2 = (self.lower_word, IMM)
                return

            if self.middle_word == dec('0110'):
                self.mnemonic = "CP"
                self.op1 = ("XH", REG)
                self.op2 = (self.lower_word, IMM)
                return

            if self.middle_word == dec('0111'):
                self.mnemonic = "CP"
                self.op1 = ("XH", REG)
                self.op2 = (self.lower_word, IMM)
                return

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

        # LD
        if self.upper_word == dec('1110'):
            if (self.middle_word >> 2) & 3 == dec('00'):
                self.mnemonic = "LD"
                self.op1 = self.r[self.middle_low]
                self.op2 = (self.lower_word, IMM)
                return
            
            if (self.middle_word >> 2) & 3 == dec('11'):
                self.mnemonic = "LD"
                self.op1 = self.r[(self.lower_word >> 2) & 3]
                self.op2 = self.r[self.lower_word & 3]
                return

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
            if self.middle_word == dec('1111'):
                self.mnemonic = "LDPY"
                self.op1 = self.r[(self.lower_word >> 2) & 3]
                self.op2 = self.r[self.lower_word & 3]
                return

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
                
        if self.upper_word == dec('1001'):
            self.mnemonic = "LBPX"
            self.op1 = ("IX", REG_DEREF)
            self.op2 = ((self.middle_word << 4) | self.lower_word, IMM)
            return

        if self.upper_word == dec('1111'):
            if self.middle_word == dec('1010'):
                self.mnemonic = "LD"
                self.op1 = ("A", REG)
                self.op2 = (self.lower_word, ADDR)
                return
            if self.middle_word == dec('1011'):
                self.mnemonic = "LD"
                self.op1 = ("B", REG)
                self.op2 = (self.lower_word, ADDR)
                return
            if self.middle_word == dec('1000'):
                self.mnemonic = "LD"
                self.op1 = (self.lower_word, ADDR)
                self.op2 = ("A", REG)
                return
            if self.middle_word == dec('1001'):
                self.mnemonic = "LD"
                self.op1 = (self.lower_word, ADDR)
                self.op2 = ("B", REG)
                return

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
            # Because each address in the ROM is 12 bits (round up to 16bits)
            # we have to double all addresses displayed since binary ninja
            # assumes each address has onle 1 byte
            value = hex(value * 2)
        elif _type == STR:
            token_type = InstructionTextTokenType.TextToken
        elif _type == REG:
            token_type = InstructionTextTokenType.RegisterToken
        elif _type == REG_DEREF:
            token_type = InstructionTextTokenType.RegisterToken

        return value, token_type

    def disasm(self, data, addr):
        instr = Instruction(data, addr)

        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, instr.mnemonic)]
        if instr.op1 is not None:
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
            value, token_type = Disassembler.parse_operand(instr.op1)
            tokens.append(InstructionTextToken(token_type, value))
        if instr.op2 is not None:
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "))

            value, token_type = Disassembler.parse_operand(instr.op2)
            tokens.append(InstructionTextToken(token_type, value))

        if instr.comment is not None:
            tokens.append(InstructionTextToken(InstructionTextTokenType.CommentToken, f" {instr.comment}"))

        return tokens, instr.branches

class PSetFinder:
    '''
    Data structure for returning the largest address smaller than the given address on retrieval
    For branch instructions, we need to query the last PSET that would normally be executed
    We also assume that each branch instruction only has a single PSET instruction that could be executed before it executes
    
    i.e Assumes there will never be basic blocks that look like this:
    .------.   .------.
    | PSET |   | PSET |
    `------'   `------'
         |         |
         v         v
       .--------------.
       | BRANCH INSTR |
       `--------------'
    '''
    DEFAULT = Instruction(b'\x0e\x41', addr=None)

    def __init__(self, bin_size=256):
        self.bin_size = bin_size
        self.psets = defaultdict(lambda: [list(), 0])
        self.history = set()
        self._size = 0

    def __len__(self):
        return self._size

    def add(self, addr:int, instr:Instruction):
        if addr in self.history:
            return

        self.history.add(addr)
        self._size += 1
        key = addr // self.bin_size
        bin = self.psets[key]
        bisect.insort(bin[0], instr, key=lambda x: x.addr)
        # Update the minimum address found in this bin
        if instr.addr < bin[1]:
            bin[1] = instr.addr

    def get(self, addr) -> Instruction:
        key = addr // self.bin_size
        bin = self.psets[key]
        while addr < bin[1]:
            key -= 1
            if key < 0:
                return PSetFinder.DEFAULT
            bin = self.psets[key]
        
        i = bisect.bisect_right(bin[0], addr, key=lambda x: x.addr)
        if i:
            return bin[0][i-1]

        return PSetFinder.DEFAULT

psets = PSetFinder()