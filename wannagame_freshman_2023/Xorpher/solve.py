from random import randint
from string import ascii_letters,digits
from pwn import xor
table = ascii_letters+digits

enc = open('ciphertext.txt').read()

enc_tup = []
i=0
while enc[i] != "}":
    if(enc[i] in table):
        enc_tup.append(enc[i:i+2])
        i+=2
        continue
    else:
        enc_tup.append(enc[i].encode())
        i+=1

enc_tup.append('}'.encode())

print('the index of revealed key are:',len(enc_tup[:-27])%8, len(enc_tup[:-26])%8)

key = xor(bytes.fromhex(enc_tup[-27])+bytes.fromhex(enc_tup[-26]),b'W1')
print('the guessed bytes key are:',key)

# kinda guessy from here, we begin with the only clue above with the bytes b'\\' of the index 0 and the inverse index 7 of the key
# so we only have 2 bytes of the key
# keep guessing the message from here will be doable since we saw many clues like '\x1fOR' or 'XO\x15' means 'XOR'
key = [b'\\',xor(b'\x1f',b'X'),xor(b'$',b'g'),xor(b'N',b'X')]
key += key[::-1]
print(key)

for i in range(len(enc_tup)):
    if(isinstance(enc_tup[i],str)):
        enc_tup[i] = xor(bytes.fromhex(enc_tup[i]), key[i%len(key)])

for msg in enc_tup:
    print(msg.decode(),end='')

