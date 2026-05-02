"""
🎯 Objective: Diffie-Hellman Shared Secret Recovery via Cryptographic Oracle

💀 Vulnerability: Key Reuse & Lack of input validation on public parameters (g, pub)

🛠️ Method:
1. Intercepts the original Diffie-Hellman exchange parameters: p, pubA, pubB, and the encrypted flag.
2. Initiates a new session with Bob, who reuses his original private key (privB).
3. Injects the original prime 'p', but poisons the parameters by sending g = pubA and pub = pubA.
4. Forces Bob to compute pubB = (pubA)^privB mod p, which mathematically equals the original shared secret.
5. Bob unwittingly prints the computed shared secret back to the terminal.
6. Hashes the leaked secret with SHA256 to derive the AES-ECB key and decrypts the original intercepted flag.
-------------------------------------------------------------------------------
"""
from pwn import *
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
r=remote('carol.challs.cyberchallenge.it', 9045)
r.recvuntil(b"p: ")
p=int(r.recvline().strip())

r.recvuntil(b"pubA: ")
pubA=int(r.recvline().strip())

r.recvuntil(b"pubB: ")
pubB=int(r.recvline().strip())

r.recvuntil(b"flag: ")
ctflag=r.recvline().strip().decode()

r.recvuntil(b"prime: ")
r.sendline(str(p).encode())

r.recvuntil(b"ator: ")
r.sendline(str(pubA).encode())

r.recvuntil(b": ")
r.sendline(str(pubA).encode())

r.recvuntil(b"essage: ")
r.sendline(b"CCIT")

r.recvuntil(b": ")
output=int(r.recvline().strip())

key = hashlib.sha256(long_to_bytes(output)).digest()[:16]
cipher=AES.new(key, AES.MODE_ECB)
flag=unpad(cipher.decrypt(bytes.fromhex(ctflag)), 16)
print(flag) 
