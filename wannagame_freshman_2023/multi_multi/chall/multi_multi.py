from random import randrange

flag = b'W1{????????????????????????????}'

base = [[randrange(1,2**10) for _ in range(len(flag))] for _ in range(len(flag))]

def MM_encrypt(base,mul):
    enc = []
    for i in range(len(base)):
        enc.append(sum(i*j for i,j in zip(base[i],mul)))
    return enc

enc = [num for num in flag]
for _ in range(100):
    enc = MM_encrypt(base,enc)

print(base)
print(enc)
        