from Crypto.Util.number import bytes_to_long, getPrime

FLAG = b"W1{??????????????????????????}"


p = getPrime(512)
q = getPrime(512)
e = 65537

n = p*p*q*q

hint1 = p + q
hint2 = p*q - p - q + 1

print("c =", pow(bytes_to_long(FLAG),e,n))
print("hint 1:", hint1)
print("hint 2:", hint2)
    


