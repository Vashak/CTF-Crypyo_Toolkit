"""
🎯 Objective: RSA LSB Oracle Exploitation & Public Key Extraction

💀 Vulnerability: Unauthenticated encryption oracle combined with a Decryption Oracle that leaks the 3 least significant bits (M % 8) of the plaintext.

🛠️ Method:
1. Extracts the hidden modulus N by requesting the ciphertexts of small integers (2, 3, 4, 9).
2. Computes the GCD of (C_2^2 - C_4) and (C_3^2 - C_9), repeatedly dividing by 2 to purge even factors and isolate the pure modulus N.
3. Requests the encrypted flag (C_flag) and the encrypted modular inverse of 8 (C_inv8).
4. Iteratively queries the decryption oracle, multiplying C_flag by C_inv8 % N at each step to shift the plaintext right by 3 bits.
5. Purifies the oracle's output by subtracting the "ghost" of previously accumulated bits, applying the formula: (output - (flag_int * inv8_pow) % n) % 8.
6. Accumulates the pure 3-bit fragments into a final large integer and converts it to the plaintext bytes.
-------------------------------------------------------------------------------
"""
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
