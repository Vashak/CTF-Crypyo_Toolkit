from Crypto.Util.number import long_to_bytes
from factordb.factordb import FactorDB

# Parametri estratti dal "cadavere"
n = 420485447340750276798905009197900250076472236951029771396372239960455176076395356078018304176360377601355361640360458283456532642841066439541542468492600074303505516012322941130021941063141150150454719702821666531692873286236281808915376205692263441233138891193279355717503716920577044748917446320341294227
e = 65537
ct = 301134324702979101601229980817712305679459272403009847977905797426967147301009753074163263516519121214477239813381651880610545484766224816075639817078022502740923937485967968414814571266684481074873719521522276878916473424098420305091570571671905697759107642819692889627538051932664261696505877765760765011

def main():
    print("[*] Connessione a FactorDB in corso...")
    f = FactorDB(n)
    f.connect()
    
    # Estrazione della lista pulita dei fattori
    risultato = f.get_factor_list()
    print(f"[+] Trovati {len(risultato)} fattori primi.")

    print("[*] Calcolo del Toziente di Eulero (phi) per Multi-Prime...")
    phi = 1
    for p in risultato:
        phi *= (p - 1)

    print("[*] Forgiatura della chiave privata (d)...")
    # Calcolo dell'inverso modulare nativo in Python 3.8+
    d = pow(e, -1, phi)

    print("[*] Decifrazione del ciphertext in corso...")
    M = pow(ct, d, n)

    print("[+] Operazione completata. Flag:")
    print(long_to_bytes(M).decode('utf-8', errors='ignore'))

if __name__ == "__main__":
    main()