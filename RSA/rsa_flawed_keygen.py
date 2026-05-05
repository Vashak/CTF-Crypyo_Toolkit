"""
🎯 Objective: RSA Key Recovery via Flawed Private Key Generation

💀 Vulnerability: The server calculates the private parameter `q` as the modular inverse of `e` modulo `p` (instead of modulo phi(N)). This creates the mathematical relationship e*q = k*p + 1. Since p and q are of equal size, k is very small (k < e). This allows for a swift brute-force attack solving a quadratic equation to recover the prime factor p.

🛠️ Method:
1. Iterates a small integer `k` from 1 to `e` (65537).
2. For each `k`, constructs the quadratic equation: k*p^2 + p - e*N = 0.
3. Calculates the discriminant (delta) and uses `gmpy2` to exact-integer square root it.
4. If delta is a perfect square, uses the quadratic formula to recover the exact integer `p`.
5. Recovers q, phi(N), and the private exponent d to decrypt the ciphertext.
-------------------------------------------------------------------------------
"""

from Crypto.Util.number import long_to_bytes, inverse
import gmpy2

def main():
    n = 7751526871113659666164486252578748649116909591277190089029732535127481176151524345597122598306249979629060800175410285871693995048150293635418099674432973398995520041393293777767941511445483996431026332997028403565850959357799371748394858804852228043653281960300204461432199938925289092169408545773233019123
    e = 65537
    ct = 4813784317490534191932457095527668318527989890720606628044645668719582196026497855453291519330699589742456932928170083183685945147596517298192372201753622124348955697985191325218715865125777867013838564483712717522945717927002788394921346947758322293598304497597954675810354257416529015463895970768411208028

    print("[*] Avvio bruteforce su k...")
    
    for k in range(1, e):
        # Calcolo del discriminante (b^2 - 4ac)
        delta = 1 - 4 * k * (-e * n)
        
        # Radice intera esatta
        radice = gmpy2.isqrt(delta)
        
        # Controllo se è un quadrato perfetto
        if radice**2 == delta:
            print(f"[+] Trovato k valido: {k}")
            
            # Calcolo di p e post-exploitation
            p = (-1 + radice) // (2 * k)
            q = n // p
            phi = (p - 1) * (q - 1)
            d = inverse(e, phi)
            
            # Decifratura
            M = long_to_bytes(pow(ct, d, n)).decode(errors='ignore')
            
            if 'CCIT' in M:
                print(f"[🔥] FLAG RECUPERATA:\n{M.strip()}")
                break

if __name__ == "__main__":
    main()