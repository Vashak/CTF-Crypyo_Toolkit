
from Crypto.Util.number import *

from pwn import *

r=remote('maybehard.challs.cyberchallenge.it', 9049)

r.recvuntil(b"> ")

r.sendline(b"1")

Ct_flag=int(r.recvline().strip())

r.recvuntil(b"> ")

r.sendline(b"2")

r.recvuntil(b"> ")

r.sendline(b"2")

C_2=int(r.recvline().strip())

r.recvuntil(b"> ")

r.sendline(b"2")

r.recvuntil(b"> ")

r.sendline(b"4")

C_4=int(r.recvline().strip())

r.recvuntil(b"> ")

r.sendline(b"2")

r.recvuntil(b"> ")

r.sendline(b"3")

C_3=int(r.recvline().strip())

r.recvuntil(b"> ")

r.sendline(b"2")

r.recvuntil(b"> ")

r.sendline(b"9")

C_9=int(r.recvline().strip())

n=GCD(C_2**2-C_4, C_3**2 - C_9)
while n%2==0:
    n=n//2
inv8=inverse(8, n)

r.recvuntil(b"> ")

r.sendline(b"2")

r.recvuntil(b"> ")

r.sendline(str(inv8).encode())

Ct_inv8=int(r.recvline().strip())

cont=0

flag_int=0
inv8_pow=1
while True:

    r.recvuntil(b"> ")

    r.sendline(b"3")

    r.recvuntil(b"> ")

    r.sendline(str(Ct_flag).encode())

    output=int(r.recvline().strip())
    true_val=(output-(flag_int*inv8_pow)%n)%8
    flag_int = flag_int + (true_val * (8**cont))

    cont+=1
    inv8_pow=(inv8_pow*inv8)%n
    Ct_flag=(Ct_flag*Ct_inv8)%n

    if cont>70: #sappiamo che la lunghezza della flag è minore di 25

        print(long_to_bytes(flag_int).decode(errors='ignore'))

        break 
