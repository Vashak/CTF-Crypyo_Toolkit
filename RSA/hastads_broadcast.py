"""
🎯 Objective: RSA Low Public Exponent (e=5) via Hastad's Broadcast Attack

💀 Vulnerability: The server encrypts the exact same plaintext message using the same small public exponent (e=5) across multiple independently generated moduli. Without random padding (like OAEP), this enables a Chinese Remainder Theorem (CRT) fusion.

🛠️ Method:
1. Establishes a persistent connection to the remote service to prevent the message array from being reshuffled.
2. Iterates systematically through the 3 possible choices.
3. For each choice, queries the server 5 times to collect a set of 5 moduli (N) and 5 ciphertexts (C).
4. Applies the Chinese Remainder Theorem (CRT) to fuse the congruences, obtaining C_tot.
5. Since M^5 < N_tot, the modular reduction is effectively bypassed. Computes the exact 5th integer root of C_tot using `gmpy2.iroot` to extract the plaintext.
6. Decodes the output and halts execution the moment the 'CCIT' flag signature is detected.

-------------------------------------------------------------------------------
"""

from Crypto.Util.number import long_to_bytes
from pwn import *
from sympy.ntheory.modular import crt 
import gmpy2

def main():
    print("[*] Inizializzazione exploit. Silenziamento log...")
    context.log_level = 'error'
    
    print("[*] Connessione al bersaglio stabilita. Ricerca della flag in corso...")
    r = remote('shell.challs.cyberchallenge.it', 9048)
    
    cont = 1
    while cont <= 3:
        print(f"[*] Analisi opzione {cont}...")
        ns = []
        cts = []
        
        # Raccolta dei 5 campioni necessari per l'esponente e=5
        for i in range(5):
            r.recvuntil(b"> ")
            r.sendline(str(cont).encode())
            r.recvuntil(b"N: ")
            ns.append(int(r.recvline().strip()))
            r.recvuntil(b"xt: ")
            cts.append(int(r.recvline().strip()))
            
        # Fusione tramite CRT e calcolo della radice quinta
        C_fuso, _ = crt(ns, cts)
        M, _ = gmpy2.iroot(C_fuso, 5)
        testo = long_to_bytes(M).decode(errors='ignore')
        
        # Controllo firma flag
        if 'CCIT' in testo:
            print(f"\n[🔥] BERSAGLIO ACQUISITO!")
            print(f"[+] Opzione corretta trovata al tentativo: {cont}")
            print(f"[+] Flag: {testo.strip()}")
            break
            
        cont += 1
        
    r.close()
    print("[*] Connessione chiusa. Pulizia tracce completata.")

if __name__ == "__main__":
    main()
