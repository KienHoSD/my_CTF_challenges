# WannaGame Freshman 2023 - EasyRSA,multi-multi,Xorpher
Lời nói đầu: Đây là những challenge mà mình ra ý tưởng, và những challenge này nếu đã làm quen với python và xài một ít thư viện thôi là có thể giải ra :smile:
## EasyRSA
Một challenge về RSA:
```python=
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
```
Nếu như các bạn chưa biết về RSA thì bạn có thể tìm hiểu từ nhiều nguồn khác nhau, trong đó có [wiki](https://en.wikipedia.org/wiki/RSA_(cryptosystem)), và nếu như các bạn đã có tìm hiểu qua mảng crypto thì RSA rất phổ biến.

Trong bài này ta cần lưu ý những chi tiết sau:
* Đầu tiên: thứ ta mã hoá không phải là văn bản, mà là từ đoạn văn bản đó chuyển ra thành số thập phân (trong đề thì hàm ```python=bytes_to_long(FLAG)``` là hàm được lấy ra từ thư viện `Crypto.Util.number` có chức năng chuyển `FLAG` từ bytes sang một dãy số nguyên thập phân tương ứng)
* Thứ hai: ta biết được `c` tức là `ciphertext` rút gọn, và thứ ta cần tìm là `bytes_to_long(FLAG)`, ta biết được `hint1` là `p+q`, `hint2` là `p*q - p - q + 1` và chính là `(p-1)*(q-1)`. Từ đây ta có thể tính ra `p` và `q` bằng cách giải phương trình bậc hai.
* Thứ ba: khi đã có `p` va `q` thì ta tính `phi` và sau đó là `d`, `phi` trong bài này sẽ được tính là `phi = (p-1)*p*(q-1)*q` vì `phi` có cách tính tuỳ theo `n` được miêu tả trong [trang wiki này](https://en.wikipedia.org/wiki/Euler%27s_totient_function#Computing_Euler's_totient_function)
* Cuối cùng: có `d` thì ta giải mã FLAG từ `c` bằng cách `pow(c,d,n)` tức là $c^d \ (mod \ n) = m = FLAG$ và FLAG đang là số nguyên, chuyển lại sang bytes thì ta sẽ có flag hoàn chỉnh.

Tổng quát:
$$c ≡ m^e \ (mod \ n)$$$$e*d ≡ 1 \ (mod \ phi)$$$$m ≡ c^d ≡ m^{e*d}≡m^1 ≡ m \ (mod \ n)$$

Mình cũng có một bài viết về cách giải một bài tương tự nhưng khác là cho `p*q` chứ không phải là `p+q` nhưng cách giải vẫn tương tự trong [link](https://hackmd.io/@QT2Y4Jw-T-2LRx5Qs1S1Kg/B1RtSY1-a)

Có nhiều phương pháp và nhiều thư viện khác nhau để giải một trong số đó thuận tiện nhất là sử dụng sympy, z3 và sagemath, hoặc không sử dụng thư viện nào.

Cách giải bằng sympy:
```python=
from sympy import *
from Crypto.Util.number import long_to_bytes

c = 3778334964020085693122279865085669931544565594340822345918989508952697153279656102136896766069941711654206670695651429514092145744418890327941850114654449578138707810321552701030453820757236624767312202504750622959336960778419511800007797894081002357542180182105523582777650174695635469165347460411204007947912540366848738081190639561262267609709489546444644666346330477076696996699487362844232320060737648554287501932392681294728341607571792807384910146769288304726543715115373869342606973465866039825063286085254744403580981503955159533367921918990386586002820616696289107796591370087382822623875066545105848859819
hint1 = 20978135329472294939914714948198369484813382661367102444419294293577936274622454399412643333395069230540445488817871514639266385242274229865025904807357796
hint2 = 107283957759499663953333972940428532630825517639279168870550288698510570747194633174133941850038669632558664539532901591228896545932212704369190692506696118889217688783240077805671896860608066777266155415930965012190554894872594664088620308010376579887314084964024069034816205917207469185957050769629280580688
e = 65537

p, q = symbols ('p q')
f1 = p + q - hint1
f2 = p*q - p - q + 1 - hint2
pq = solve([f1,f2], [q, p])

# because p and q can change place, it will return 2 solution with the same result
# be awared of the type of the result by reading log! change it to python 'int'
p = int(pq[0][0])
q = int(pq[0][1])

# check p and q
print(p)
print(q)
#8834805679464844020925796104886974592664830317414710365329969804733937434423380695047726909138242788361145823286696262594746297737839443746541458234044059
#12143329650007450918988918843311394892148552343952392079089324488843998840199073704364916424256826442179299665531175252044520087504434786118484446573313737
assert p+q == hint1, "Wrong p and q"
assert p*q - p - q + 1 == hint2, "Wrong p and q"

# calculating phi,d,n and get flag!
phi = (p-1)*p*(q-1)*q 
d = pow(e,-1,phi)
n = p*p*q*q
print('Flag',long_to_bytes(pow(c,d,n)))
#Flag b'W1{0k_th1s_1s_e4sy_RSA_1nd33d}'
```

## multi-multi
Đây là đề:
```python=
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
```
Nếu để ý thì sẽ biết ngay đây là phép nhân ma trận vuông với một vector và lặp lại nhiều lần với vector kết quả của phép nhân trước là vector bị nhân của phép nhân sau. Việc này lặp lại 100 lần nên output khá lớn. Ta cần tìm lại vector gốc của toàn bộ vòng lặp nhân ma trận này vì đó chính là `flag` (`enc = [num for num in flag]`)

Nói đến ma trận, có một đặc tích cần lưu ý đó là kích thước 'shape' của ma trận, khi nhân một ma trận với một ma trận khác hay một vector thì ta cần lưu ý đến điều đó. 

Với cách giải thì để thuận tiện mình có thể dùng sagemath hoặc numpy. Sau đây là cách giải bằng sagemath:
```python=
from sage.all import *
from ast import literal_eval

with open('output.txt') as f:
    base = literal_eval(f.readline())
    enc = literal_eval(f.readline())

base = matrix(base)
enc = matrix(enc).T
print(enc.parent())
print(base.parent())
#Full MatrixSpace of 32 by 1 dense matrices over Integer Ring
#Full MatrixSpace of 32 by 32 dense matrices over Integer Ring

#Solve right of matrix multiplication to find vector enc(n-1) "base * enc(n-1) = enc(n)"
#until enc(0) -> flag
for _ in range(100):
    enc = base.solve_right(enc)

print(enc.list())
print(''.join(bytes([i]).decode() for i in enc.list()))
#[87, 49, 123, 109, 52, 116, 114, 49, 120, 95, 49, 115, 95, 114, 51, 97, 108, 108, 121, 95, 99, 48, 48, 108, 95, 114, 49, 103, 104, 116, 63, 125]
#W1{m4tr1x_1s_r3ally_c00l_r1ght?}
```
## Xorpher
Đây là đề:
```python=
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
```
Đây là nội dung file ciphertext.txt
```
082f26 4e0c15 333726647737282e 2e30 733b332e392a267a6f 2433312a2c78 2234 3d 20797b332832392937 7f2d 31333526 752c2a2c30223b 752a3734393530. 013e 353330737a25, 29342a7871 26 3f282d6562222928 352666732233353220 7d733a, 3d 307f7b332b39 1f0c44 202e2c342231 752229 28352a607f222b3025 2173 21353337222d 63302e323b 25647332323932243a 772d263025342a65. 0e3a 332b73 20283228222d62 2c21 3d293a 7b26342f3d2026 752229 3e22 716326342f3923 7964 2828342231617f3022 37292c6178 33343929 627e26 37393e 75772d 3e39 3173602626303923. 5f3734 2c352a7b77313e 3122317f62 2e2f 332b7762 2e28 2e30 652a2a2c3022 6279 2e312c2b267b732d33, 262d72 372f3d28 377e73 1f130e 2c667331262835282d 7f30 3f332a3363622233353329227a7a3a 3532223b66732d34352a22. 57 343531372f73 31222c3926377f7824 041315 (7f.22. 32307f7824 283422 65772e22 37223a 702c35 242831 7933222e3d332a7978 2832 332b73 342f333022 72773726) 242a667e2635 3534 627e2635393a283173 30283139332a7b7330 292f2227 702c35 342e277f7824 3532212c647b2233353329 7f78 243d2f2230 612b222e39 2d79 33262e282e20637a2235 2f222063642a3325 2e30 6426362935352672. 133439 1b5944 24352c2f2664 2a34 3321377378 322f3923 7f78 2433313736627331 313d2b34776426 2833 2e777d26 2e393126646526 3932202a78732635353220 7b793122 382e25707f20323028. 427e26 3a302624 7f30 0b6d{3b2664_762f_24737b7b7329_6d29_75647437286c}
```

Xem lướt qua nội dung file ciphertext.txt thì có thể thấy được flag được nằm ở cuối, và ta biết flag format là 'W1{...}', từ đó suy ra nếu ta biết được vị trí key tương xứng với 2 bytes '0b6d' thì ta biết được một phần của key.

Nói đến key thì key chỉ có 4 bytes nhưng được làm kéo dài lên 8 bytes bằng cách cộng thêm 4 bytes đầu lật ngược lại (`key[::-1]`) ở dòng 10 (việc lật ngược lại ở đoạn cuối không ảnh hưởng đến key), nên phương án brute-force là có thể thực hiện nhưng sẽ khá lâu (256^4 = 4294967296) vì thế nên dựa vào những gợi ý từ `ciphertext` ta có thể dò ra từng byte của key và giải mã `message` sẽ nhanh hơn.

Đây là code giải:
```python=
from random import randint
from string import ascii_letters,digits
# import xor from pwntool library to xor 2 bytes 
# or you can code the function yourself :P
from pwn import xor
table = ascii_letters+digits

enc = open('ciphertext.txt').read()

# read the ciphertext.txt
# the hex will remain and the symbol not in table ().{}_ will be encoded
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
#the index of revealed key are: 7 0

key = xor(bytes.fromhex(enc_tup[-27])+bytes.fromhex(enc_tup[-26]),b'W1')
print('the guessed bytes key are:',key)
#the guessed key bytes are: b'\\\\'

# kinda guessy from here, we begin with the only clue above with the bytes b'\\' of the index 0 and the inverse index 7 of the key
# so we only have 2 bytes of the key
# keep guessing the message from here will be doable since we saw many clues like '\x1fOR' or 'XO\x15' means 'XOR'
key = [b'\\',xor(b'\x1f',b'X'),xor(b'$',b'g'),xor(b'N',b'X')]
key += key[::-1]
print(key)
#[b'\\', b'G', b'C', b'\x16', b'\x16', b'C', b'G', b'\\']

for i in range(len(enc_tup)):
    if(isinstance(enc_tup[i],str)):
        enc_tup[i] = xor(bytes.fromhex(enc_tup[i]), key[i%len(key)])

for msg in enc_tup:
    print(msg.decode(),end='')
#The XOR operator is extremely common as a component in more complex ciphers. By itself, using a constant repeating key, a simple XOR cipher can trivially be broken using frequency analysis. If the content of any message can be guessed or otherwise known then the key can be revealed. Its primary merit is that it is simple to implement, and that the XOR operation is computationally inexpensive. A simple repeating XOR (i.e. using the same key for xor operation on the whole data) cipher is therefore sometimes used for hiding information in cases where no particular security is required. The XOR cipher is often used in computer malware to make reverse engineering more difficult. The flag is W1{x0r_1s_c0mm0n_1n_cr7pt0}
```
# Thoughts
Bên trên là cách giải 3 bài của mình, mình rất vui khi đã có thể được tham gia ra đề và được các bạn feedback. Và cũng mong các bạn đã có những giây phút căng thẳng nhưng vui vẻ khi đã tham gia Wannagame Freshman năm nay :satisfied:, nếu các bạn có thắc mắc gì hoặc mình có sai sót chỗ nào ở các bài trên thì cứ nhắn mình qua discord hoặc qua mail nhé. 
Và vẫn như thường lệ, thank you for reading!

#KienSD


