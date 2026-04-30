"""
🎯 Objective: Recover Diffie-Hellman Shared Secret & Decrypt AES-ECB.

💀 Vulnerability: Weak Diffie-Hellman exponent generation (limited search space).

🛠️ Method:
1. Intercepts public parameters p, g, pubA, and pubB.
2. Identifies the weak exponent range [0, 1024] from the source code.
3. Brute-forces the private exponent 'privA' by checking g^i ≡ pubA (mod p).
4. Computes the shared_secret as pubB^privA (mod p).
5. Derives the 16-byte AES key using SHA256(long_to_bytes(shared_secret)).
6. Decrypts the AES-ECB ciphertext and removes PKCS7 padding to reveal the flag.
-------------------------------------------------------------------------------
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
import hashlib

# Parametri recuperati dal cadavere
p = 139379733354483189501227871110064527157682987958433427156390202678064149815642568826477911770307752913621426076298507790818439936280449152741721879461096492477608431936689120104356856262262510907004792117855182041421333215157243722734389759734373030448619917500336774214725967664965383449965717319942422012769
g = 141766002927079634436012416932426270195633516375074194269497658683856933939749443631920896002088564385320471756930651924877164463775158556657562652267307493472917448586968014693578189551533885711413705919878486107011929558061609254391556828943430904948541065524176574683093670163402084986719526042666437454093
pubA = 66016709400498362636875074602841729207604794529650288520206492814919780360783708766932535497512319649726274113961638853865431404545264600640090701462114753302958560839001532056864200400813840304804168459012583090289433312917793089693811381875506133051726976084529081221968387648987529391439097289229126508657
pubB = 133227005774287036263116319213286327328023826794360062545765483165358414788214818135925261563492163513299648752612241934102242044547030469122144101231822302310174491118256008699381279457737273945228911100642427945143296557018573202722398182706517728025099779057026709510256921227257159199663754440944499687527
ct_hex = "fe7d573c3f2bd0320ca5e175ca7ba52586f1da4354644b641e775fed1fddc3988a689ab5b0e5ed557093bb0c24690e75"

# 1. Recupero del segreto tramite brute-force sull'esponente corto
nbits = 1024
privA = -1

print("[*] Avvio trivellazione dell'esponente...")
for i in range(nbits + 1):
    if pow(g, i, p) == pubA:
        privA = i
        print(f"[+] Trovato privA: {privA}")
        break

if privA != -1:
    # 2. Calcolo del segreto condiviso
    shared_secret = pow(pubB, privA, p)
    
    # 3. Derivazione chiave (identica alla logica del server)
    key = hashlib.sha256(long_to_bytes(shared_secret)).digest()[:16]
    
    # 4. Decrittazione AES-ECB
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_flag = bytes.fromhex(ct_hex)
    
    try:
        decrypted_pad = cipher.decrypt(encrypted_flag)
        flag = unpad(decrypted_pad, 16)
        print(f"\n[🔥] SERVER BREACHED. FLAG: {flag.decode()}")
    except Exception as e:
        print(f"[!] Errore durante la decrittazione: {e}")
else:
    print("[!] Fallimento: privA non trovato nel range specificato.")