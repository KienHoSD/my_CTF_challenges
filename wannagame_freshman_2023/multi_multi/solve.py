from sage.all import *
from ast import literal_eval

with open('output.txt') as f:
    base = literal_eval(f.readline())
    enc = literal_eval(f.readline())

base = matrix(base)
enc = matrix(enc).T
print(enc.parent())
print(base.parent())

for _ in range(100):
    enc = base.solve_right(enc)
print(enc.list())
print(''.join(bytes([i]).decode() for i in enc.list()))