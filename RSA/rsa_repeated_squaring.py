"""
🎯 Objective: RSA Decryption with Even Exponent (Repeated Squaring)
💀 Vulnerability: Non-invertible Public Exponent (e = 2^16)
🛠️ Method:
1. Factors the modulus N by exploiting the flawed generation of primes (N ≈ 8 * x^2).
2. Extracts p and q using gmpy2.isqrt(N // 8) and a local search.
3. Identifies the inability to compute the private key 'd' due to e = 65536 being even.
4. Exploits p ≡ 3 (mod 4) to efficiently compute modular square roots.
5. Builds a "Root Expansion Tree" to calculate all 65,536 possible roots of the ciphertext modulo p.
6. Relies on the condition M < p to extract the flag directly from the tree leaves without needing CRT.
-------------------------------------------------------------------------------
"""
from Crypto.Util.number import long_to_bytes, inverse

import gmpy2

n=143781684205389590010553134380517839058800341945951643846073964866638089941840311649560443936018651523969097963156967461283254598766182074871111838992505412018060806895987954123451280765476361794492545159179574840809250122003659558280110600523086073453593454301077841968713229457908552385130837363633326415539737047470209206503059358918963869499435888844742538325735934527946583750967433382950305568735891613971448304718286959958935899838597289022343543761412307578886703487271378307843705503950924777583617267981168241797094503210187196429696116962343134338115484421605658032478064979001495536373830780524756850984403
e=65536
ct=46766905580151190418167803800165852091449208838188815017482849743414798774037472205063154540852982120181535046497442975708675054661850345368214412560288799186010974747853074590266319384716017651039242789559088620469062334248752936623909170122538837706046848747293902057629461004056101310160515075424004388699736985826186428545210061908019625815935902910426753776224094948966703940659182850761935616877161509987727056412539500582660909361043016267769727096915307634477041094152402621008747657745037328401665898055629694301506033482146343496620423943272589768958861265192857140142751775400356925215981924417004378907958

x=gmpy2.isqrt(n//8)

p=1

for i in range(800):

    p_copia=x+i

    if n % p_copia ==0:

        p=p_copia

        break

if p==1: 

    for i in range(800):

        p_copia=x-i

        if n%p_copia==0:

            p=p_copia

            break

q=n//p
print(q)
print("  ")
print(p)

if p%4==3:
    print("godo")
if q%4==3:
    print("rigodo")
if q*p==n:
    print("asd")

# Inizializziamo con il ciphertext ridotto modulo p
candidati = [ct % p]

print(f"[*] Inizio estrazione radici modulari (16 passi)...")

for i in range(16):
    nuovi_candidati = []
    esponente = (p + 1) // 4
    
    for c in candidati:
        # Calcoliamo la prima radice r
        r = pow(c, esponente, p)
        
        # Ogni numero ha DUE radici: r e -r (ovvero p - r)
        nuovi_candidati.append(r)
        nuovi_candidati.append(p - r)
        
    candidati = nuovi_candidati
    # Debug opzionale: print(f"Passo {i+1}: {len(candidati)} candidati")

print(f"[+] Estrazione completata. Analisi di {len(candidati)} potenziali messaggi...")

# Ora cerchiamo la flag tra i 65536 risultati
for cand in candidati:
    try:
        # Convertiamo il numero in bytes
        msg = long_to_bytes(cand)
        if b"CCIT" in msg:
            print(f"\nFLAG TROVATA: {msg.decode(errors='ignore')}")
            break
    except:
        continue
