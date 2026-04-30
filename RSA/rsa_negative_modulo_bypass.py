"""
🎯 Objective: Extract RSA public key `n` & Bypass Decryption Oracle divisor checks.

💀 Vulnerability: 
- The server computes Modulo operations on un-sanitized negative inputs.
- Python handles negative modulos by wrapping around (e.g., -c_flag^d % n = n - m_flag).
- The divisor check firewall (`m % used == 0`) fails against `n - m_flag`.
- Universal Modulo Trap: If -1 is added to the `used` array first, EVERY subsequent decryption fails because X % -1 == 0 is always True.

🛠️ Method:
1. Parse the initial encrypted flag (`c_flag`).
2. CRITICAL ORDER: First, send the negative ciphertext (`-c_flag`) to the Decryption Oracle. 
3. The server decodes it to `-m_flag` and applies modulo `n`, yielding `n - m_flag`. This bypasses the firewall since only `m_flag` is in the `used` list at this point.
4. Retrieve the decrypted payload (`n - m_flag`).
5. Send `-1` to the Encryption Oracle. The server computes (-1)^e % n, returning `n - 1`. Adding 1 reveals the secret modulus `n`.
6. Calculate `m_flag = n - payload`, and decode to ASCII.
-------------------------------------------------------------------------------
"""

from Crypto.Util.number import long_to_bytes
from pwn import remote, context

# context.log_level = 'debug' # De-commentare per il debug di rete

r = remote('oracle.challs.cyberchallenge.it', 9042)

# 1. Rubiamo il ciphertext originale
r.recvuntil(b"Encrypted flag: ")
c_flag = int(r.recvline().strip())

# 2. Bypassiamo il firewall inviando PRIMA -c_flag al Decrypt Oracle
# Se lo facessimo dopo, l'1 o il -1 in 'used' bloccherebbero tutto (qualsiasi numero % -1 fa 0)
r.recvuntil(b"> ")
r.sendline(b"2")
r.recvuntil(b"Ciphertext > ")
r.sendline(str(-c_flag).encode())

r.recvuntil(b"Decrypted: ")
decriptato = int(r.recvline().strip())

# 3. Rubiamo 'n' inviando -1 all'Encrypt Oracle
r.recvuntil(b"> ")
r.sendline(b"1")
r.recvuntil(b"Plaintext > ")
r.sendline(b"-1")

r.recvuntil(b"Encrypted: ")
n_meno_uno = int(r.recvline().strip())
n = n_meno_uno + 1

# 4. Calcolo finale della flag
X = n - decriptato
flag = long_to_bytes(X)

print(f"\n[🔥] SERVER BREACHED. FLAG: {flag.decode('utf-8')}")
r.close()
