#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Created By  : Pasero Christian
# Created Date: SS 2022
# version = '1.0'
# ---------------------------------------------------------------------------
"""  Bachelor project - SS 2022 
SAT-Solver attack for Spongent-160 (Elephant) [https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf]. 
The attack uses the z3-SAT Solver and operates on 64bit preimage length and an
adjustable hashing output length of arbitrary size <= 128
"""
# ---------------------------------------------------------------------------
################################# IMPORTS ###########################################
import time
from z3 import *

################################# CONSTANTS ###########################################
ROUND_NUM  = 1
HASH_LEN   = 32
HASH_VALUE = 0x0



################################# TEST HASHES #########################################
# Testhashes 128bit
allHashes128 = [
    BitVecVal(0x35166640400100ffff7f0200ffff3fff, 128),
    BitVecVal(0xf99f45524281c15ff99f45524281c15f, 128),
    BitVecVal(0xa5d90e13d86fc740a5d90e13d86fc740, 128),
    BitVecVal(0x28e4a717f4bd562628e4a717f4bd5626, 128),
    BitVecVal(0xc481db8ba4484ebc481db8ba4484eb56, 128),
    BitVecVal(0x307824dba14dd818307824dba14dd818, 128),
    BitVecVal(0xc2dbc7c4d564be3cc2dbc7c4d564be3c, 128),
    BitVecVal(0x6e8450c381f2f0c56e8450c381f2f0c5, 128),
    BitVecVal(0x224ee586ca4c2f11224ee586ca4c2f11, 128),
    BitVecVal(0x34a86e19af7619a434a86e19af7619a4, 128)]



############################## SAT SOLVER CHECKER ####################################
def checkSat(s: Solver, hash: BitVec, p_img: BitVec, start_time: time) -> None:
    '''checks if it is satisfiable and prints the values'''
    if s.check() == sat:
        end_time = time.time()
        m = s.model()
        print(f"Rounds  : {ROUND_NUM}")
        print(f"HashLen : {HASH_LEN}")
        print(f"Hash    : {hex(int(str(m[hash])))[:2+(int(HASH_LEN))]}")
        print(f"F_Hash  : {hex(int(str(m[hash])))}")
        print(f"F_PImg  : {hex(int(str(m[p_img])))}")
        print(f"exe_time: {math.ceil(end_time - start_time)}s")
    else:
        print("ERROR")



def buildHash(s: Solver, IS: list, hash: BitVec) -> BitVec:
    '''transforms the IS into a 160 bit hash'''
    for i in range(20):
        s.add(Extract(160-1-8*i, 160-8*(i+1), hash) == IS[i])
    return hash



########################################### PI function #######################################
def Pi(i: int) -> int:
    '''PI helper function for permutation'''
    if i != 159:
        return int(i*160/4) % 159
    else:
        return 159
    

    
########################################### p_Layer ###########################################
counter_pLayer = 0
def pLayer(s: Solver, IS_: list) -> list:
    '''pLayer the actual permutation without sBox'''
    global counter_pLayer
    ret = list()

    for i in range(20):
        counter_pLayer += 1
        obj = BitVec(f"pLayer_obj({counter_pLayer})[{i}]", 8)
        s.add(obj == 0x0)
        ret.append([obj])

    for i in range(20):
        for j in range(8):
            permutatedBitNo = Pi(8*i+j)
            y = int(permutatedBitNo/8)

            # build current 8bit
            counter_pLayer += 1
            curr = BitVec(f"pLayer_curr({counter_pLayer})", 8)
            test = BitVec(f"p({counter_pLayer})", 1)

            s.add(test == Extract(j,j,IS_[i]))
            s.add(Extract(permutatedBitNo-8*y, permutatedBitNo-8*y, curr) == Extract(j,j,IS_[i]))
            for k in range(8):
                if k != permutatedBitNo-8*y:
                    s.add(Extract(k, k, curr) == 0x0)
            
            # add to array construct
            curr_transformed = BitVec(f"pLayer_currTransformed({counter_pLayer})", 8)
            s.add(curr_transformed == ret[y][-1] ^ curr)
            ret[y].append(curr_transformed)   
    ret_list = list()
    for i in range(20):
        ret_list.append(ret[i][-1]) 
    return ret_list



########################################### S_BOX ###########################################
counter_sbox = 0
def sBox(s: Solver, val_: int) -> BitVec:
    '''Selfmade S-Box'''
    global counter_sbox
    counter_sbox += 1

    first_half = [BitVec(f"sBox_firstHalf({counter_sbox})_{i}", 1) for i in range(4)]
    for i in range(4): 
        s.add(first_half[i] == Extract(i, i, val_))
    
    secnd_half = [BitVec(f"sBox_secndHalf({counter_sbox})_{i}", 1) for i in range(4, 8, 1)]
    for i in range(4, 8, 1): 
        s.add(secnd_half[i-4] == Extract(i, i, val_))

    ret = BitVec(f"sBox_ret_({counter_sbox})", 8)
    for i, x in enumerate([first_half, secnd_half]):
        x_0 = (~x[3]&((~x[2]&(x[1]^x[0]))|(x[2] & x[0])))|(x[3]&((~x[2]&(~(x[1]^x[0])))|(x[2]&(~x[0]))))
        x_1 = (~x[3]&((~x[2]&(~x[0]))|(x[2]&(~(x[1]^x[0])))))|(x[3]&((~x[2]&(~x[1]))|(x[2]&x[1])))
        x_2 = (~x[3]&((~x[2]&(~x[1]))|(x[2]&x[1])))|(x[3]&((x[2]&x[0])|(~x[2]&(~(x[1]^x[0])))))
        x_3 = (~x[3]&((~x[2]&(~(x[1]&x[0])))|(x[2]&x[1]&x[0])))|(x[3]&((~x[2]&(x[1]^x[0]))|(x[2]&~x[1])))
        s.add(Extract((i*4)+0, (i*4)+0, ret) == x_0)
        s.add(Extract((i*4)+1, (i*4)+1, ret) == x_1)
        s.add(Extract((i*4)+2, (i*4)+2, ret) == x_2)
        s.add(Extract((i*4)+3, (i*4)+3, ret) == x_3)
    return ret



####################################### L_COUNTER ###########################################
counter_lCounter = 0
def lCounter(s: Solver, IV_: BitVec) -> BitVec:
    global counter_lCounter
    counter_lCounter += 1
    temp = BitVec(f"lCounter_temp_{counter_lCounter}", 8)
    ret = BitVec(f"lCounter_ret_{counter_lCounter}", 8)
    s.add(Extract(7, 1, temp) == Extract(6, 0, IV_))
    s.add(Extract(0, 0, temp) == Extract(6, 6, IV_) ^ Extract(5, 5, IV_))
    s.add(ret == temp & 0x7f)
    return ret



####################################### RETNUO_CL ###########################################
counter_retnuoCL = 0
def retnuoCl(s: Solver, IV_: BitVec) -> BitVec:
    global counter_retnuoCL
    counter_retnuoCL += 1
    ret = BitVec(f"retnuoCL_{counter_retnuoCL}", 8)
    for i in range(8):
        counter_retnuoCL += 1
        s.add(Extract(i,i,ret) == Extract(7-i, 7-i, IV_))
    return ret



#################################### PERMUTATION ###########################################
def permutation(s: Solver, IS_: list, IV_: BitVecVal) -> list:
    '''Spongent permutation function'''
    IV = IV_
    IS = IS_
    for r in range(ROUND_NUM):
        IS_pre = [BitVec(f"IS_perm_pre_r({r})_[{i}]", 8) for i in range(20)]
        s.add(IS_pre[0] == IS[0] ^ IV)
        for i in range(1,19,1):
            s.add(IS_pre[i] == IS[i])
        INV_IV = retnuoCl(s, IV)   
        s.add(IS_pre[19] == IS[19] ^ INV_IV)
        IV = lCounter(s, IV)
        IS = [BitVec(f"IS_perm_r({r})_[{i}]", 8) for i in range(20)]
        for i in range(20):
            s.add(IS[i] == sBox(s, IS_pre[i]))  
        IS = pLayer(s, IS)
    return IS



#################################### INIT ###########################################
def init(s: Solver, M_1: str):
    '''Initializes the InternalState IS and the initialization vector IV'''
    IV = BitVec("IV_init", 8)
    s.add(IV == 0x75)
    IS = [BitVec(f"IS_init[{i}]", 8) for i in range(20)]
    for i in range(20):
        if i < 8:
            s.add(IS[i] == Extract(i*8+7, i*8, M_1))
        elif i == 8: 
            s.add(IS[i] == 0x80)
        else: 
            s.add(IS[i] == 0x0)
    return IS, IV



################################ NORMAL EXECUTION ####################################
def forward_calc():
    '''This is the normal hash function execution, where the message is given and
    the hash is calculated'''
    s = Solver()
    start = time.time()
    # 64bit message
    M_1 = BitVec("M_1_inp", 64)
    s.add(M_1 == 0x89056337)
    # initialize x and y vectors
    IS, IV = init(s, M_1)
    IS = permutation(s, IS, IV)
    hash_empty = BitVec("Hash_out", 160)
    hash = buildHash(s, IS, hash_empty)
    checkSat(s, hash, M_1, start)



####################################   ATTACK   ####################################
def backward_attack():
    '''This is the SAT-Solver attack'''
    s = Solver()
    start = time.time()
    # 64bit message
    M_1 = BitVec("M_1_inp", 64)
    # crypto hash function
    IS, IV = init(s, M_1)
    IS = permutation(s, IS, IV)
    hash_empty = BitVec("Hash_out", 160)
    hash = buildHash(s, IS, hash_empty)
    s.add(Extract(159, 159-HASH_LEN*4, hash) == Extract(127, 127-HASH_LEN*4, HASH_VALUE))

    checkSat(s, hash, M_1, start)



#################################### Attributes ####################################
def setAttr():
    '''sets the attributes which were given a paramater'''
    if len(sys.argv) != 4:
        print("Usage: python3 attack.py ROUNDNUM HASHLEN[bit] HashIndex[0-9]")
        exit()
    global ROUND_NUM
    global HASH_LEN
    global HASH_VALUE
    ROUND_NUM   = int(sys.argv[1])
    HASH_LEN    = int(int(sys.argv[2])/4)
    HashIndex   = int(sys.argv[3])
    HASH_VALUE  = allHashes128[HashIndex]



####################################   MAIN   ####################################
def main():
    setAttr()
    #forward_calc()    # normal hash usage
    backward_attack()  # SAT-Solver attack

if __name__ == '__main__':
    main()



