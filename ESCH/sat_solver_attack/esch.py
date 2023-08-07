import sys


mlen = 16
ROUND_NUM = 11
BIG_STEPS = ROUND_NUM #default: 11
SMALL_STEPS = ROUND_NUM - 4 #default: 7

RCON = [0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738,
    0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D]

def ROT(x: int, n: int):
    return ((x & 0xffffffff) >> n) | ((x << (32-n) & 0xffffffff)) #masking with 32 bits if SAT not needed
def ELL(x: int):
    return ROT((x ^ ((x << 16) & 0xffffffff)), 16)

def ARXBOX(x: int, y: int, c: int):
    r = [[31, 24], [17, 17], [0, 31], [24, 16]]
    for v in r:
        x = x + ROT(y, v[0]) & 0xffffffff #masking with 32 bits if SAT not needed
        y = y ^ ROT(x, v[1])
        x = x ^ c
    return x, y


def linearLayer(x: list, y: list, brans: int):
    #Feistel function (adding to y part)
    tmp = 0
    b = int(brans/2)
    for i in range(b):
        tmp = tmp ^ x[i]
    tmp = ELL(tmp); 
    for i in range(b):
        y[i+b] = y[i+b] ^ (tmp ^ y[i])

    #Feistel function (adding to x part)
    tmp = 0
    for i in range(b):
        tmp = tmp ^ y[i]
    tmp = ELL(tmp)
    for i in range(b):
        x[i+b] = x[i+b] ^ (tmp ^ x[i])


    #Branch swap of the x part
    x[0], x[1], x[2], x[3], x[4], x[5] = x[4], x[5], x[3], x[0], x[1], x[2]
    #Branch swap of the y part
    y[0], y[1], y[2], y[3], y[4], y[5] = y[4], y[5], y[3], y[0], y[1], y[2]

    return x, y


def sparkleRef(x: list, y: list, step_size: int):
    brans = 6
    for i in range(step_size):
        #Add step counter + ARXBox layer
        for j in range(brans):
            if j == 0:
                x[j], y[j] = ARXBOX(x[j], y[j] ^ RCON[i%8], RCON[j])
            elif j == 1:
                x[j], y[j] = ARXBOX(x[j], y[j] ^ i, RCON[j])
            else:
                x[j], y[j] = ARXBOX(x[j], y[j], RCON[j])

        #Linear layer
        linearLayer(x, y, brans)
    return x, y



def add_msg_blk(x: list, y: list, message):
    #creating the buffer
    buffer = list()
    buffer.append(message & 0xffffffff)
    buffer.append((message >> 32) & 0xffffffff)
    for _ in range(4):
        buffer.append(0)

    #padding
    buffer[2] = 0x80

    #Feistel function part 1:
    tmpx = 0 #only 32 bits!
    tmpy = 0 #only 32 bits!
    for i in range(0, 6, 2):
        tmpx = tmpx ^ buffer[i]
        tmpy = tmpy ^ buffer[i+1]

    #Feistel function part 2:
    tmpx = ROT((tmpx ^ ((tmpx << 16) & 0xffffffff)), 16); #masking with 32 bits if SAT not needed 
    tmpy = ROT((tmpy ^ ((tmpy << 16) & 0xffffffff)), 16); #masking with 32 bits if SAT not needed 
    
    for i in range(3):
        x[i] = x[i] ^ buffer[2*i] ^ tmpy
        y[i] = y[i] ^ buffer[2*i+1] ^ tmpx    
    return x, y



def finalize(x: int, y: int):
    buffer = [x[0], y[0], x[1], y[1], 0, 0, 0, 0]
    x, y = sparkleRef(x, y, SMALL_STEPS)
    for i in range(2):
        buffer[2*i + 4] = x[i]
        buffer[2*i + 5] = y[i]
    return buffer



def processMessage(x: list, y: list, message):
    y[2] =  1 << 24 # addition of constant M_1
    x, y = add_msg_blk(x, y, message)
    x, y = sparkleRef(x, y, BIG_STEPS)
    IS = finalize(x, y) 
    return IS
    


def permutation(x: list, y: list, message):
    IS = processMessage(x, y, message)
    return IS



def init():
    x = [0 for _ in range(6)]
    y = [0 for _ in range(6)]
    return x, y


def printbuffer(buffer):
    print("buffer: ", end="")
    for i in range(6):
        print(f"{buffer[i]:08x}-", end="")



def printHash(IS: list):
    # flip numbers pairwise 0123456789 -> 8967452301
    hash = list()
    for i in IS:
        for j in range(4):
            hash.append(i >> (j * 8) & 0xff)
    for i in hash:
        print("{:02X}".format(i), end="")


def printxy(x, y):
    print("x: ", end="")
    for i in range(6):
        print(f"{x[i]:08x}", end="-")

    print("\ny: ", end="")
    for i in range(6):
        print(f"{y[i]:08x}", end="-")
    print()



def printIS(IS: list):
    c = 0
    print("IS: ", end="")
    for i in IS:
        if c == 6:
            return
        print(f"{hex(i)[2:]}-", end="")
        c += 1
        


def setAttr():
    if len(sys.argv) != 4:
        print("Usage: python3 esch.py ROUNDNUM HASHLEN[bit] HashIndex[0-9]")
        exit()
    global ROUND_NUM
    global HashLen
    global BIG_STEPS
    global SMALL_STEPS

    ROUND_NUM = int(sys.argv[1])
    BIG_STEPS = ROUND_NUM #default: 11
    SMALL_STEPS = ROUND_NUM - 4 #default: 7
    HashLen = int(sys.argv[2])
    HashIndex = int(sys.argv[3])


def main():
    setAttr()
    message = 0x0000000002805FF9
    x, y = init()
    IS = permutation(x, y, message)
    printIS(IS)
    print()
    printHash(IS)

if __name__ == '__main__':
    main()