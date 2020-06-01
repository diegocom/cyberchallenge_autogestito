# Write-Up gruppo 1

- [Write-Up gruppo 1](#write-up-gruppo-1)
  - [Start](#start)
  - [Sito](#sito)
    - [Hint 1](#hint-1)
  - [Disk](#disk)
    - [Hint 2](#hint-2)
    - [Forensics](#forensics)
    - [Reverse Engineering](#crackme)
      - [Hint 3](#hint-3)
    - [Steganography](#stenography)
    - [Cracking](#cracking)
      - [Hint 4](#hint-4)
  - [Conclusione](#conclusione)
  - [Extra](#extras)

## Start

La challenge inizia con uno zip.

```bash
unzip challenge_gruppo_1.zip
```

All'interno dello zip troviamo diversi file:

- **get_flag.py** : script python che una volta fornita la password corretta
  stampa la flag
- **start** : eseguibile per l'inizio della challenge
- **stage1.txt** : file di benvenuto

  Osserviamo lo start fare cose (LOL). Alla fine ci indirizza ad un
  [sito web](https://joshuachp.github.io/CTF/CCIT_challenge/).

## Sito

Accediamo al sito e troviamo che il campo username è vulnerabile a SQLI ber il
bypass dell'autenticazione.

```sql
admin' --
```

Questo ci permette di scaricare un file `disk`.

> Il sito non utilizza un database in quanto è una pagina statica. Anche lo se
> lo script è minified, con un po' di reversing si può benissimo trovare la
> funzione del download, però non è pratico in quanto per questioni di tempo la
> query è molto semplice.

### Hint 1

Nel source del sito possiamo trovare un commento suggerisce di utilizzare SQL
Injection.

## Disk

Utilizzando il comando `file` su disk possiamo vedere:

```bash
disk: Linux rev 1.0 ext2 filesystem data, ...
```

Essendo un file-system procediamo quindi a creare una cartella dove eseguire il
mount

```bash
mkdir mnt
sudo mount disk mnt
```

Nella cartella `mnt` troviamo i seguenti file:

- **next_stage.txt** : un testo che come all'inizio ci indica la strada da
  proseguire.
- **helpful.png** : immagine con Clippy che ci lascia un messaggio

Clippy nel suo messaggio cita un eseguibile di cui fare il reverse engineering,
però non abbiamo al momento nessun eseguibile.

### Hint 2

Analizziamo quindi il contenuto del file `next_stage.txt`

```bash
strings next_stage.txt
strings -10 next_stage.txt
```

Notiamo una stringa in base64, decodificata proseguiamo ad analizzarla notando
che è stato applicato uno shift

```bash
echo "RnIgZnJ2IG95YnBwbmdiIHZhIGdoZ2d2IGRocmZndiBPVkEgY2ViaW4gbiBzbmVndiBoYW4gSk5ZWCA6KQo=" | base64 -d | tr ‘n-za-mN-ZA-M’ ‘a-zA-Z’
# Oppure se si ha installati bsd_games
echo "RnIgZnJ2IG95YnBwbmdiIHZhIGdoZ2d2IGRocmZndiBPVkEgY2ViaW4gbiBzbmVndiBoYW4gSk5ZWCA6KQo=" | base64 -d | rot13
```

Unendo le varie informazioni trovate sappiamo che sono stati eliminati dei file
e ci viene citato `binwalk`.

### Forensics

Il filesystem mantiene i dati scritti su disco anche dopo l'eliminazione dato
che vengono solo eliminati i nodi e considerato come freespace. Per estrarre i
dati ci sono vari modi: testdisk, ext-undelete, scalpel... Noi mostreremo un
metodo utilizzando binwalk.

Come suggerito proviamo a utilizzare binwalk su disk per trovare tutti i dati
contenuti, nelle nuove versioni è necessario utilizzare il tag `-b`.

Facendo un prima analisi sul file disk possiamo notare che contiene file di
estensione nota e che quando abbiamo fatto il mount non erano presenti

```bash
strings -10 disk | grep -i "[a-z_]*\.[a-z]*"
strings | head
# next_stage.txt
# sneaky.tar.gz
# helpful.png
```

Una volta visto l'esistenza di un file non presente alla montatura procediamo
con l'estrazione e l'analisi dei files utilizzando binwalk con la flag `-e`.

```bash
binwalk -e -b disk
cd _disk.extracted/
file *
tar -xvf 7400
```

Il tar contiene i seguenti files:

- **final_stage.txt** : testo
- **crackme** : eseguibile

> Utilizzando lo strumento testdisk è possibile riconoscere il file rimosso, ma
> non è possibile l'estrazione

### Reverse Engineering

Analizzando crackme troviamo che dal main viene chiamata una funzione da un
array di funzioni nominato `table`. La funzione chiamata è la funzione `j`, dato
che viene l'indice viene determinato dal calcolo di `modular_exponentiation`
sulla base di parametri statici.

```C++
argv_to_int = atoi(*(char **)(param_2 + 8));
table_index = modular_exponentiation(3,0x2b,7);
cVar1 = *(table + (ulong)table_index * 8)((ulong)argv_to_int);
```

Proseguendo l'analisi della funzione `j` notiamo che al suo interno chiama una
funzione di controllo (`fourth_check`) passando come argomento del binary.
`fourth_check` divide il valore che abbiamo inserito in 4 variabili tramite
operazioni binarie che utilizza poi in un sistema lineare a quattro incognite.
La funzione `j` controllerà poi i risultati di questo sistema con i valori
contenuti in un array inizializzato all'interno della procedura.

Conoscendo tutti questi valori possiamo quindi creare un sistema lineare dove
poniamo come incognite le quattro parti in cui il nostro valore di ingresso è
stato diviso e una volta che abbiamo ottenuto il valore andiamo a fare il
reverse dell'operazione di `>>` per ottenere il valore corretto.

```python
import numpy as np
import math

""" fourth_check() - from ghidra
uint32_t a = n & 0xFF;
uint32_t b = (n >> 8) & 0xFF;
uint32_t c = (n >> 16) & 0xFF;
uint32_t d = (n >> 24) & 0xFF;

uint32_t v1 = 'J' * a + 'o' * b + 'j' * c + 'o' * d;
uint32_t v2 = 'D' * a + 'I' * b + 'O' * c + '!' * d;
uint32_t v3 = 'Z' * a + 'A' * b + 'W' * c + 'A' * d;
uint32_t v4 = 'R' * a + 'U' * b + 'D' * c + 'O' * d;

uint32_t vals[4] = {61319, 38111, 48787, 48939};
"""

def char_to_str(chrs):
return [ord(c) for c in chrs]

incognite = np.array([char_to_str("Jojo"), char_to_str("DIO!"), char_to_str("ZAWA"), char_to_str("RUDO")])
valori = np.array([61319, 38111, 48787, 48939])
risultato = np.linalg.solve(incognite, valori)
print("Values are: {}".format(risultato)) # Values are: [198.  96. 146. 185.]

values = [198, 96, 146, 185]
values.reverse()
binary = ["{0:08b}".format(b) for b in values]
print("Value: {}".format(int("".join(binary), 2))) # 3113377990
```

Eseguiamo quindi crackme passando come parametro il valore calcolato e otteniamo
un HASH(SHA2).

```bash
./crackme 3113377990
# 0051377D1EE813EBFB59991D9165D88EC8C28C51AB37268A01DE386D00AE873AE34051D74CEEF2E457AB2D06BF283BEE87D0A209242B004DC27892DA6DB1AE1C
```

#### Hint 3

Nell'eseguibile viene eseguito un controllo tra la stringa "stuck" e una
variabile di nome `hint`. Se andiamo a controllare il valore della variabile, ci
consiglia di trovare dinamicamente la funzione chiamata dal main o di cambiare
il tipo della variabile `table` in un array di funzioni per capire quale di
queste chiami. La stringa la possiamo notare eseguendo strings del nostro
eseguibile.

### Steganography

Consideriamo l'immagine `helpful.png`

```bash
strings helpful.png
# at Least you're putting Significant effort into this challenge
```

Dato il suggerimento proviamo a vedere se abbiamo qualcosa nei
[bit meno significativi](https://www.boiteaklou.fr/Steganography-Least-Significant-Bit.html).
Utilizzando il codice fornito all'interno della pagina web otteniamo il nostro
messaggio nascosto.

```python
import base64
from PIL import Image

image = Image.open("./helpful.png")
extracted = ''
pixels = image.load()
for x in range(0,image.width):
r,g,b = pixels[x,0]
extracted += bin(r)[-1]
extracted += bin(g)[-1]
extracted += bin(b)[-1]

chars = []
for i in range(len(extracted)//8):
byte = extracted[(i*8):(i+1)*8]
chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))

flag = ''.join(chars)
print(flag) # This website might help you a lot: https://ecavicc.github.io/cyberchallenge/
```

> Un altro tool più popolare utilizzabile è zsteg in ruby per ricavare
> direttamente il base64

### Cracking

Andiamo a forzare l'hash che abbiamo ottenuto dall'eseguibile per ottenere la
password che ci permetterà di ottenere la flag. Per crackare l'hash andremo a
utilizzare hashcat fornendo una wordlist, si può anche trovare la soluzione su
[CrackStation](https://crackstation.net/)

```bash
hashcat -a 0 -m 1700 hash rockyou.txt
# Mr.Pickles
```

#### Hint 4

Il sito che abbiamo estratto  dall'immagine contiene il simbolo # e un gattino
da qui possiamo collegare i due elementi e ottenere `hashcat`. Inoltre il link 
presente infondo alla pagina, che porta alla canzione We Will Rock You, vuole
essere un suggerimento a utilizzare una wordlist di supporto.

## Conclusione

Eseguiamo il file python per ottenere la flag

```bash
echo "Mr.Pickles" > passwd
python3 get_flag.py < passwd
```

`FLAG{i_7urn3d_mys31f_i1n70_4_pick13}`

## Extras

Piccoli easter-egg presenti nella sfida :smile:

- **Forgot Password**: premere più volte `forget password` potrebbe aiutare.
- **Copy Pasta**: Crackme potrebbe esprimersi su Rick & Morty.
- **Hello There**: Il sito nascosto da Clippy - con un gran icona - potrebbe 
  avere un saluto altrettanto nascosto.
