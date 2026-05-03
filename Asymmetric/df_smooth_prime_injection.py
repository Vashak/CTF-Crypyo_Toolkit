"""
🎯 Objective: Diffie-Hellman Private Key Recovery via Smooth Prime Injection

💀 Vulnerability: Lack of validation on the mathematical structure of the provided prime 'p' (only size and primality are checked).

🛠️ Method:
1. Forges a custom prime p = K + 1 where K is a B-smooth number (product of many small primes).
2. Sends the poisoned p, along with g=2 and a dummy public value, to Bob.
3. Bypasses the server's asserts (p is prime, p >= NBITS).
4. Bob unwittingly calculates pubB_new = 2^privB mod p and returns it.
5. Computes the discrete logarithm of pubB_new using SymPy, which executes instantly because p-1 is heavily composite (Pohlig-Hellman attack).
6. Recovers Bob's original private key (privB).
7. Reconstructs the original shared secret using Alice's original pubA and original prime.
8. Derives the AES-ECB key and decrypts the intercepted flag.
-------------------------------------------------------------------------------
"""
from pwn import *
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import isPrime, long_to_bytes
from sympy import discrete_log, primerange
import random

context.log_level = 'error'

NBITS = 2048
piccoli_primi = list(primerange(2, 10000))

print("[*] Fucina attivata: Generazione del modulo avvelenato (Pohlig-Hellman Trap)...")

while True:
    K = 2
    while K.bit_length() < NBITS:
        K = K * random.choice(piccoli_primi)
    
    if isPrime(K + 1):
        p = K + 1
        break

print(f"[+] Modulo avvelenato generato con successo (bit length: {p.bit_length()})")

print("[*] Inizializzazione connessione al server...")
r = remote('carol.challs.cyberchallenge.it', 9046)

# --- Fase 1: Estrazione Parametri Originali ---
r.recvuntil(b"p: ")
p_originale = int(r.recvline().strip())
r.recvuntil(b"pubA: ")
pubA_originale = int(r.recvline().strip())
r.recvuntil(b"pubB: ")
pubB_originale = int(r.recvline().strip())
r.recvuntil(b"flag: ")
ctflag_originale = r.recvline().strip().decode()

# --- Fase 2: Iniezione Parametri Avvelenati ---
print("[*] Iniettando parametri malevoli...")
r.recvuntil(b"prime: ")
r.sendline(str(p).encode())
r.recvuntil(b"ator: ")
r.sendline(b"2")
r.recvuntil(b"value: ")
r.sendline(str(pubB_originale).encode())
r.recvuntil(b"essage: ")
r.sendline(b"PWNED")

# --- Fase 3: Cattura dell'Oracolo ---
r.recvuntil(b"pubB: ")
nuovo_pubB = int(r.recvline().strip())

# --- Fase 4: L'Estrattore e Ripristino del Segreto ---
print("[*] Calcolo del Logaritmo Discreto in corso (SymPy)...")
privB = discrete_log(p, nuovo_pubB, 2)
print(f"[+] Chiave privata di Bob estratta: {privB}")

print("[*] Decrittazione della flag originale...")
shared_secret = pow(pubA_originale, privB, p_originale)
key = hashlib.sha256(long_to_bytes(shared_secret)).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
flag = unpad(cipher.decrypt(bytes.fromhex(ctflag_originale)), 16)

print(f"\n[🔥] BERSAGLIO DISTRUTTO. FLAG: {flag.decode()}")
