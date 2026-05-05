"""
🎯 Objective: RSA Modulus Collision via Birthday Paradox

💀 Vulnerability: The RSA modulus N is generated using a restricted precomputed pool of only 500 primes. Due to the Birthday Paradox, requesting multiple public keys results in a high probability of two different moduli sharing a common prime factor.

🛠️ Method:
1. Connects to the remote service using `pwntools`.
2. Repeatedly requests 50 encrypted flags, storing the corresponding moduli (N) and ciphertexts (ct).
3. Iterates through the collected moduli to find a collision where `gcd(N_i, N_j) > 1`, extracting the common prime factor `p`.
4. Calculates the second factor `q = N // p` and identifies the specific ciphertext encrypted with this compromised N.
5. Reconstructs the Euler's totient `phi`, forges the private key `d`, and decrypts the flag.

-------------------------------------------------------------------------------
"""
from pwn import *

from Crypto.Util.number import long_to_bytes

from math import gcd

r=remote('paas.challs.cyberchallenge.it', 9047)

e=65537

ns=[]

cts=[]

for i in range(50): #assicuriamoci al 1000% che ci sia un compleanno

    r.recvuntil(b"> ")

    r.sendline(b"1")

    r.recvuntil(b"N: ")

    ns.append(int(r.recvline().strip()))

    r.recvuntil(b"xt: ")

    cts.append(int(r.recvline().strip()))

p=0

q=0

for i in range(len(ns)):

    for j in range(i+1, len(ns)):

        if gcd(ns[i], ns[j])>1:

            p=gcd(ns[i], ns[j])

            q=ns[i]//p

            break

    if p!=0:

        break

N=q*p

ctflag=0

for i in range(len(ns)):

    if(N==ns[i]):

        ctflag=cts[i]

phi=(p-1)*(q-1)

d=pow(e, -1, phi)

M=pow(ctflag, d, N)

print(long_to_bytes(M).decode('utf-8', errors='ignore')) 
