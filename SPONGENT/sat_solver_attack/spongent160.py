import sys


mlen = 16
ROUND_NUM = 80 #80


def printIS(IS):
    for i, obj in enumerate(IS):
        print(f"IS[{i}] = {hex(obj)}")
    exit()

def Pi(i):
    if i != 159:
        return int(i*160/4) % 159
    else:
        return 159


def pLayer(IS):
    tmp = [0 for _ in range(20)]
    for i in range(20):
        for j in range(8):
            permutatedBitNo = Pi(8*i+j)
            y = int(permutatedBitNo/8)
            tmp[y] = tmp[y] ^ ((IS[i] >> j) & 0x1) << (permutatedBitNo - 8*y)
    return tmp

def sBox(IS_obj):
    first_half = [((IS_obj >> (i)) & 0x1) for i in range(4)]
    secnd_half = [((IS_obj >> (i+4)) & 0x1) for i in range(4)]
    res = list()

    for x in [first_half, secnd_half]:
        #x0 -> (~a∧((~b∧(c⊻d)) ∨ (b∧d))) ∨ (a∧((~b∧(~(c⊻d)))∨(b∧~d)))
        res.append((not(x[3]) and ((not(x[2]) and (x[1]^x[0])) or (x[2] and x[0]))) or (x[3] and ((not(x[2]) and (not(x[1]^x[0]))) or (x[2] and (not(x[0]))))))
        #x1 -> (~a∧((~b∧~d) ∨ (b∧~(c⊻d)))) ∨ (a∧((~b∧~c) ∨ (b∧c)))
        res.append((not(x[3]) and ((not(x[2]) and (not(x[0]))) or (x[2] and (not(x[1]^x[0]))))) or (x[3] and ((not(x[2]) and (not(x[1]))) or (x[2] and x[1]))))
        
        #x2 -> (~a∧((~b∧~c)∨(b∧c)))∨(a∧((b∧d)∨(~b∧(~(c⊻d)))))
        res.append((not(x[3]) and ((not(x[2]) and (not(x[1]))) or (x[2] and x[1]))) or (x[3] and ((x[2] and x[0]) or (not(x[2]) and (not(x[1]^x[0]))))))
    
        #x3 -> (~a∧((~b∧~(c∧d)) ∨ (b∧c∧d)))∨(a∧((~b∧(c⊻d))∨(b∧~c)))
        res.append((not(x[3]) and ((not(x[2]) and (not((x[1] and x[0])))) or (x[2] and x[1] and x[0]))) or (x[3] and ((not(x[2]) and (x[1]^x[0])) or (x[2] and (not(x[1]))))))

    result = 0
    for i in range(8):
        result |= res[i]<<i
    return result


def lCounter(lfsr):
    lfsr = (lfsr << 1) | ((lfsr & 0x40) >> 6) ^ ((lfsr & 0x20) >> 5) 
    lfsr = lfsr & 0x7f
    return lfsr


def retnuoCl(lfsr):
    # turns around 12345678 -> 87654321
    return ((lfsr & 0x01) <<7) | ((lfsr & 0x02) << 5) | ((lfsr & 0x04) << 3) | ((lfsr & 0x08) << 1) | ((lfsr & 0x10) >> 1) | ((lfsr & 0x20) >> 3) | ((lfsr & 0x40) >> 5) | ((lfsr & 0x80) >> 7);		

def permutation(IS, IV):
    for r in range(ROUND_NUM):
        IS[0] = IS[0] ^ IV
        INV_IV = retnuoCl(IV)
        IS[19] = IS[19] ^ INV_IV
        IV = lCounter(IV)

        for i in range(20):
            IS[i] = sBox(IS[i])
        
        IS = pLayer(IS)

    return IS
        


def init(M_1):
    IV = 0x75
    IS = [ (M_1 >> (i * 8)) & 0xFF for i in range(20)]
    IS[8] = 0x80
    return IV, IS


def setAttr():
    if len(sys.argv) != 4:
        print("Usage: python3 xoodyak.py ROUNDNUM HASHLEN[bit] HashIndex[0-9]")
        exit()
    global ROUND_NUM
    global HashLen

    ROUND_NUM = int(sys.argv[1])
    HashLen = int(sys.argv[2])


def main():
    setAttr()
    M_1 = 0xacacacacacacacac
    IV, IS = init(M_1)
    IS = permutation(IS, IV)
    printIS(IS)
    exit()

if __name__ == '__main__':
    main()
    