#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Created By  : Pasero Christian
# Created Date: SS 2022
# version = '1.0'
# ---------------------------------------------------------------------------
"""  Bachelor project - SS 2022 
SAT-Solver attack for Esch-256 (sparkle) [https://sparkle-lwc.github.io]. 
The attack uses the z3-SAT Solver and operates on 64bit preimage length and an
adjustable hashing output length of arbitrary size <= 128
"""
# ---------------------------------------------------------------------------
################################# IMPORTS ###########################################
from z3 import *
import time

################################# CONSTANTS ###########################################
RCON = [0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738,
    0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D]
ROUND_NUM = 11
BIG_STEPS = ROUND_NUM       #default: 11
SMALL_STEPS = ROUND_NUM - 4 #default: 7
HASH_LEN = 32
HASH_VALUE = BitVecVal(0x0,128)

################################# TEST HASHES #########################################
# Testhashes 128bit
allHashes128 = [
    BitVecVal(0x192415816174853a192415816174853a, 128),
    BitVecVal(0xf99f45524281c15ff99f45524281c15f, 128),
    BitVecVal(0xa5d90e13d86fc740a5d90e13d86fc740, 128),
    BitVecVal(0x28e4a717f4bd562628e4a717f4bd5626, 128),
    BitVecVal(0xc481db8ba4484ebc481db8ba4484eb56, 128),
    BitVecVal(0x307824dba14dd818307824dba14dd818, 128),
    BitVecVal(0xc2dbc7c4d564be3cc2dbc7c4d564be3c, 128),
    BitVecVal(0x6e8450c381f2f0c56e8450c381f2f0c5, 128),
    BitVecVal(0x224ee586ca4c2f11224ee586ca4c2f11, 128),
    BitVecVal(0x34a86e19af7619a434a86e19af7619a4, 128)]


########################## EXTRACTS THE HASH FROM THE IS #############################
def getHashFromIs(s: Solver, IS: list):
    '''extracts the hash, it is done in the following format
    IS: 01234567-89abcdef-.... -> EXTRACTION -> hash: 67452310-efcdab89'''
    hash = BitVec("hash", 256)
    pos_hsh = 255
    for obj in IS:
        pos_obj = 0
        for i in range(0, 32, 8):
            s.add(Extract(pos_hsh-i, pos_hsh-7-i, hash) == Extract(pos_obj+7+i, i, obj))        
        pos_hsh -= 32
    return hash



##################################### ELL #######################################
ctr_ELL = 0 # ELL counter for unique SAT BitVec naming
def ELL(s: Solver, x_: BitVec):
    '''makes a permutation to a 32 bit vector (xoring and rotating)'''
    global ctr_ELL
    x = BitVec(f"ELL_({ctr_ELL})", 32)
    s.add(x == RotateRight((x_ ^ (x_ << 16)), 16))
    ctr_ELL += 1
    return x



################################## FINALIZE ####################################
def finalize(s: Solver, x: list, y: list):
    '''makes a permutation to x and y and sets up the hash output in a buffer form'''
    buffer = [BitVec(f"finalize_[{i}]", 32) for i in range(8)]
    for i in range(2):
        s.add(buffer[2*i] == x[i])
        s.add(buffer[2*i + 1] == y[i])
    x, y = sparkleRef(s, x, y, SMALL_STEPS)
    for i in range(2):
        s.add(buffer[2*i + 4] == x[i])
        s.add(buffer[2*i + 5] == y[i])
    return buffer



############################### LINEAR LAYER ####################################
ctr_linearLayer = 0 # linear layer counter for unique SAT BitVec naming
def linearLayer(s: Solver, x_: list, y_: list, brans_: int):
    '''This is the linear layer of the permutation'''
    global ctr_linearLayer

    #Feistel function (adding to y part)
    b = int(brans_/2)
    tmp = [BitVec(f"lL({ctr_linearLayer})_tmp_addy_{i}", 32) for i in range(b+1)]
    ctr_linearLayer += 1
    s.add(tmp[0] == BitVecVal(0x0, 32))
    for i in range(b):
        s.add(tmp[i+1] == tmp[i] ^ x_[i]) 
    tmp = ELL(s, tmp[b])
    y = [BitVec(f"lL({ctr_linearLayer})_y_{i}", 32) for i in range(7)]
    ctr_linearLayer += 1
    for i in range(b):
        s.add(y[i] == y_[i])
        s.add(y[i+b] == y_[i+b] ^ (tmp ^ y_[i]))

    #Feistel function (adding to x part)
    tmp = [BitVec(f"lL({ctr_linearLayer})_tmp_addx_{i}", 32) for i in range(b+1)]
    ctr_linearLayer += 1
    s.add(tmp[0] == 0x0)
    for i in range(b):
        s.add(tmp[i+1] == tmp[i] ^ y_[i]) 
    tmp = ELL(s, tmp[b])
    x = [BitVec(f"lL({ctr_linearLayer})_x_{i}", 32) for i in range(7)]
    ctr_linearLayer += 1
    s.add(x[0] == x_[0])
    for i in range(b):
        s.add(x[i] == x_[i])
        s.add(x[i+b] == x_[i+b] ^ (tmp ^ x_[i]))

    #Branch swapping
    x_out = [x[4], x[5], x[3], x[0], x[1], x[2]]
    y_out = [y[4], y[5], y[3], y[0], y[1], y[2]]
    return x_out, y_out



################################ ARXBOX ######################################
ctr_ARXBOX = 0 #arxbox counter for unique SAT BitVec naming
def ARXBOX(s: Solver, x_: BitVec, y_: BitVec, c: BitVecVal):
    '''ARXBOX gets called from sparkleRef, is a 32 bit permutation'''
    global ctr_ARXBOX
    x = [BitVec(f"ARXBOX_x_ctr({ctr_ARXBOX})_{i}", 32) for i in range(8+1)]
    s.add(x[0] == x_)
    y = [BitVec(f"ARXBOX_y_ctr({ctr_ARXBOX})_{i}", 32) for i in range(4+1)]
    s.add(y[0] == y_)

    r = [[31, 24], [17, 17], [0, 31], [24, 16]]
    for i, v in enumerate(r):
        s.add(x[2*i+1] == x[2*i] + RotateRight(y[i], v[0]))
        s.add(y[i+1] == y[i] ^ RotateRight(x[2*i+1], v[1]))
        s.add(x[2*i+2] == x[2*i+1] ^ c)
    ctr_ARXBOX += 1
    return x[-1], y[-1]



########################### SPARKLE REF FUNCTION ################################
ctr_sparkleRef = 0 #sparkle counter for unique SAT BitVec naming
def sparkleRef(s: Solver, x_: list, y_: list, step_size: int):
    '''Sparkle permutation with linear layer included, changes x and y'''
    global ctr_sparkleRef

    x = [[BitVec(f"sR_x_({ctr_sparkleRef})[{i}]", 32) for i in range(6)]]
    ctr_sparkleRef += 1
    y = [[BitVec(f"sR_y_({ctr_sparkleRef})[{i}]", 32) for i in range(6)]]
    ctr_sparkleRef += 1
    for i in range(6):
        s.add(x[0][i] == x_[i])
        s.add(y[0][i] == y_[i])
    brans = 6
    #Add step counter + ARXBox layer
    for i in range(step_size):
        x.append([BitVec(f"sR_x_({ctr_sparkleRef})[{i}]", 32) for i in range(6)])
        ctr_sparkleRef += 1
        y.append([BitVec(f"sR_y_({ctr_sparkleRef})[{i}]", 32) for i in range(6)])
        ctr_sparkleRef += 1
        for j in range(brans):
            if j == 0:
                t_x, t_y = ARXBOX(s, x[-2][j], y[-2][j] ^ RCON[i%8], RCON[j])
            elif j == 1:
                t_x, t_y = ARXBOX(s, x[-2][j], y[-2][j] ^ i, RCON[j])
            else:
                t_x, t_y = ARXBOX(s, x[-2][j], y[-2][j], RCON[j])
            s.add(x[-1][j] == t_x)
            s.add(y[-1][j] == t_y)
        #Linear layer
        x_ll, y_ll = linearLayer(s, x[-1], y[-1], brans)
        x.append(x_ll)
        y.append(y_ll)
    return x[-1], y[-1]



########################### ADD MESSAGE BLOCK ################################
def add_msg_blk(s: Solver, x_: list, y_: list, message_: BitVec):
    '''adds the message to x and y'''
    #create buffer
    buffer = [BitVec(f"amb_plog_buffer[{i}]", 32) for i in range(6)]
    s.add(buffer[0] == Extract(31,0,message_))
    s.add(buffer[1] == Extract(63, 32, message_))
    for i in range(3, 6, 1):
        s.add(buffer[i] == 0x0)
    #padding
    s.add(buffer[2] == 0x80)

    #Feistel function part 1:
    tmpx = [BitVec(f"amb_tmpx[{i}]", 32) for i in range(9)]
    s.add(tmpx[0] == 0x0)
    tmpy = [BitVec(f"amb_tmpy[{i}]", 32) for i in range(9)]
    s.add(tmpy[0] == 0x0)
    ctr = 1
    for i in range(0, 6, 2):
        s.add(tmpx[ctr] == tmpx[ctr-1] ^ buffer[i])
        s.add(tmpy[ctr] == tmpy[ctr-1] ^ buffer[i+1]) 
        ctr += 1
    #Feistel function part 2:
    tmpx_f = ELL(s, tmpx[ctr-1])
    tmpy_f = ELL(s, tmpy[ctr-1])
    x = [BitVec(f"amb_x[{i}]", 32) for i in range(6)]
    y = [BitVec(f"amb_y[{i}]", 32) for i in range(6)]
    for i in range(6):
        if i < 3:
            s.add(x[i] == x_[i] ^ buffer[2*i] ^ tmpy_f)
            s.add(y[i] == y_[i] ^ buffer[2*i+1] ^ tmpx_f)
        else:
            s.add(x[i] == x_[i])
            s.add(y[i] == y_[i])
    return x, y



############################## PERMUTATION FUNCTION ################################
def processMessage(s: Solver, x_: list, y_: list, message_: BitVec):
    '''This is the Esch permutation'''
    x = [BitVec(f"pM_x[{i}]", 32) for i in range(6)]
    y = [BitVec(f"pM_y[{i}]", 32) for i in range(6)]
    #addition of constant M_1
    for i in range(6):
        if i == 2:
            #padding
            s.add(y[2] == (0x1 << 24))
            s.add(x[2] == x_[2])
        else:
            s.add(y[i] == y_[i])
            s.add(x[i] == x_[i])

    x, y = add_msg_blk(s, x, y, message_)
    x, y = sparkleRef(s, x, y, BIG_STEPS)
    IS = finalize(s, x, y) 
    return IS



############################# INITIALIZATION OF x AND y #############################
def init(s: Solver):
    '''returns x, y = {0}'''
    x = [BitVec(f"init_x[{i}]", 32) for i in range(6)]
    y = [BitVec(f"init_y[{i}]", 32) for i in range(6)]
    for i in range(6):
        s.add(x[i] == 0)
        s.add(y[i] == 0)
    return x, y



############################## SAT SOLVER CHECKER ####################################
def checkSat(s: Solver, hash: BitVec, p_img: BitVec, start_time: time):
    '''checks if it is satisfiable and prints the values'''
    if s.check() == sat:
        end_time = time.time()
        m = s.model()
        print(f"Rounds  : {ROUND_NUM}  ->  BIG_STEPS({BIG_STEPS}) | SMALL_STEPS({SMALL_STEPS})")
        print(f"HashLen : {HASH_LEN}")
        print(f"Hash    : {hex(int(str(m[hash])))[:2+(int(HASH_LEN))]}")
        print(f"F_Hash  : {hex(int(str(m[hash])))}")
        print(f"F_PImg  : {hex(int(str(m[p_img])))}")
        print(f"exe_time: {math.ceil(end_time - start_time)}s")
    else:
        print("ERROR")



################################ NORMAL EXECUTION ####################################
def forward_calc():
    '''This is the normal hash function execution, where the message is given and
    the hash is calculated'''
    s = Solver()
    start = time.time()
    # 64bit message
    M_1 = BitVec("M_1_inp", 64)
    s.add(M_1 == 0xcccccccccccccccc)
    # initialize x and y vectors
    x, y = init(s)
    # crypto hash function
    IS = processMessage(s, x, y, M_1)
    #extract hash
    hash = getHashFromIs(s, IS)
    checkSat(s, hash, M_1, start)



####################################   ATTACK   ####################################
def backward_attack():
    '''This is the SAT-Solver attack'''
    s = Solver()
    start = time.time()
    # 64bit message
    M_1 = BitVec("M_1_inp", 64)
    # initialize x and y vectors
    x, y = init(s)
    # crypto hash function
    IS = processMessage(s, x, y, M_1)
    #extract hash
    hash = getHashFromIs(s, IS)
    s.add(Extract(255, 255-HASH_LEN*4, hash) == Extract(127, 127-HASH_LEN*4, HASH_VALUE))
    checkSat(s, hash, M_1, start)



#################################### Attributes ####################################
def setAttr():
    '''sets the attributes which were given a paramater'''
    if len(sys.argv) != 4:
        print("Usage: python3 attack.py ROUNDNUM HASHLEN[bit] HashIndex[0-9]")
        exit()
    global ROUND_NUM
    global HASH_LEN
    global BIG_STEPS
    global SMALL_STEPS
    global HASH_VALUE
    ROUND_NUM   = int(sys.argv[1])
    HASH_LEN    = int(int(sys.argv[2])/4)
    HashIndex   = int(sys.argv[3])
    HASH_VALUE  = allHashes128[HashIndex]

    BIG_STEPS   = ROUND_NUM
    if ROUND_NUM >= 4:
        SMALL_STEPS = ROUND_NUM - 4
    else:
        SMALL_STEPS = ROUND_NUM



####################################   MAIN   ####################################
def main():
    setAttr()
    #forward_calc()    # normal hash usage
    backward_attack()  # SAT-Solver attack

if __name__ == '__main__':
    main()