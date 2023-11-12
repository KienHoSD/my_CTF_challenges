from random import randint
from string import ascii_letters,digits

table = ascii_letters+digits

with open('message.txt') as flag:
    flag = flag.read()

key = bytearray([randint(0,256) for _ in range(4)]) 
key = (key + key[::-1])[::-1]

ciphertext = "".join(str(hex(key[i%len(key)]^ord(flag[i]))[2:].zfill(2)) if flag[i] in table else flag[i] for i in range(len(flag)))

with open('ciphertext.txt','w') as enc:
    enc.write(ciphertext)