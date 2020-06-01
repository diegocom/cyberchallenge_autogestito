# CyberChallenge - gruppo 3

## Binary

Il binario in questione richiede prima l'inserimento di un codice, quindi fa partire a schermo il comando [sl](https://github.com/mtoyoda/sl) accuratamente incattivito, per poi controllare la stringa inserita e stampare a video la flag. 

Usando strings, notiamo che il binario non contiene stringe significative. Inoltre il binario è molto grosso, stranamente. Usare strace o ltrace non da gli effetti sperati, perché il binario evita il tracing (ma anche non fosse, vi dico che non vedreste nulla di significativo)

Proviamo a disassemblarlo e vedere che c'è dentro. Per fortuna include i simboli di debug (ho pensato a stripparlo, ma poi diventava forse troppo difficile 🤯). Procediamo quindi con un qualsiasi tool di disassemby, per esempio il comando `objdump`:

```bash
objdump -M intel -d binary
```

Interessiamoci della funzione `main()`. Il resto sono varie funzioni del comando `sl`, che possiamo benissimo ignorare:



```nasm
main:
    ; solito set dello stack frame
    31e0:	55                   	push   rbp
    31e1:	53                   	push   rbx
    31e2:	31 db                	xor    ebx,ebx
    31e4:	48 81 ec 18 01 00 00 	sub    rsp,0x118
    31eb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
    ; ignoriamo tutti i primi 100 segnali
    31f0:	89 df                	mov    edi,ebx
    31f2:	be 01 00 00 00       	mov    esi,0x1
    31f7:	83 c3 01             	add    ebx,0x1
    31fa:	e8 f1 fe ff ff       	call   30f0 <signal@plt>
    31ff:	83 fb 64             	cmp    ebx,0x64
    3202:	75 ec                	jne    31f0 <main+0x10>
    ; non voglio essere tracciato!
    3204:	ba 01 00 00 00       	mov    edx,0x1
    3209:	31 c9                	xor    ecx,ecx
    320b:	31 f6                	xor    esi,esi
    320d:	31 ff                	xor    edi,edi
    320f:	31 c0                	xor    eax,eax
    3211:	e8 2a ff ff ff       	call   3140 <ptrace@plt>
    3216:	ba 01 00 00 00       	mov    edx,0x1
    321b:	48 83 f8 ff          	cmp    rax,0xffffffffffffffff
    321f:	0f 84 a1 00 00 00    	je     32c6 <main+0xe6>
    3225:	48 8d 3d d8 2d 00 00 	lea    rdi,[rip+0x2dd8]        # 6004 <_IO_stdin_used+0x4>
    322c:	31 c0                	xor    eax,eax
    322e:	48 8d 5c 24 10       	lea    rbx,[rsp+0x10]
    ; stampa di inserisci la chiave
    3233:	e8 58 fe ff ff       	call   3090 <printf@plt>
    3238:	48 8d 74 24 0c       	lea    rsi,[rsp+0xc]
    323d:	48 8d 3d d4 2d 00 00 	lea    rdi,[rip+0x2dd4]        # 6018 <_IO_stdin_used+0x18>
    3244:	31 c0                	xor    eax,eax
    ; lettura della chiave
    3246:	e8 15 ff ff ff       	call   3160 <__isoc99_scanf@plt>
    324b:	31 c0                	xor    eax,eax
    ; ora chiamo SL per perdere tempo
    324d:	e8 1e 0c 00 00       	call   3e70 <slmain>
    ; arriva il bello
    ; rax = key!
    3252:	48 63 44 24 0c       	movsxd rax,DWORD PTR [rsp+0xc]
    ; i = 0
    3257:	31 d2                	xor    edx,edx
    ; rsi = table (cosa sarà mai table?) 
    ; una struct { char c; int i; } 
    ; NB: c viene per questioni di allineamento ad occupare 4 byte!
    3259:	48 8d 35 c0 6e 00 00 	lea    rsi,[rip+0x6ec0]        # a120 <table>
    ; char c = table[key].c
    3260:	0f b6 0c c6          	movzx  ecx,BYTE PTR [rsi+rax*8]
    3264:	48 63 ea             	movsxd rbp,edx
    ; key = table[key].i ovvero computo nuova chiave
    3267:	48 63 44 c6 04       	movsxd rax,DWORD PTR [rsi+rax*8+0x4]
    ; flag[i] = c (= table[rax].c)
    326c:	88 0c 13             	mov    BYTE PTR [rbx+rdx*1],cl
    ; i++
    326f:	48 83 c2 01          	add    rdx,0x1
    ; } while (c != '{')
    3273:	80 f9 7b             	cmp    cl,0x7b
    3276:	75 e8                	jne    3260 <main+0x80>
    3278:	48 8d 3d a1 2d 00 00 	lea    rdi,[rip+0x2da1]        # 6020 <_IO_stdin_used+0x20>
    327f:	89 44 24 0c          	mov    DWORD PTR [rsp+0xc],eax
    3283:	48 01 eb             	add    rbx,rbp
    3286:	48 8d 6c 24 0f       	lea    rbp,[rsp+0xf]
    ; stampo Now decrypting flag
    328b:	e8 d0 fd ff ff       	call   3060 <puts@plt>
    3290:	48 8d 3d 84 2d 00 00 	lea    rdi,[rip+0x2d84]        # 601b <_IO_stdin_used+0x1b>
    3297:	31 c0                	xor    eax,eax
    ; stampo CCIT (non è parte della flag)
    3299:	e8 f2 fd ff ff       	call   3090 <printf@plt>
    329e:	66 90                	xchg   ax,ax
    ; stampo la flag al contrario 
    ; while (i-- > 0) puts(flag[i])
    32a0:	0f be 3b             	movsx  edi,BYTE PTR [rbx]
    32a3:	48 8b 35 96 80 7a 00 	mov    rsi,QWORD PTR [rip+0x7a8096]        # 7ab340 <stdout@@GLIBC_2.2.5>
    32aa:	48 83 eb 01          	sub    rbx,0x1
    32ae:	e8 2d fe ff ff       	call   30e0 <putc@plt>
    32b3:	48 39 eb             	cmp    rbx,rbp
    32b6:	75 e8                	jne    32a0 <main+0xc0>
    32b8:	48 8d 3d fe 2d 00 00 	lea    rdi,[rip+0x2dfe]        # 60bd <_IO_stdin_used+0xbd>
    ; un a capo in fondo non guasta mai
    32bf:	e8 9c fd ff ff       	call   3060 <puts@plt>
    32c4:	31 d2                	xor    edx,edx
    32c6:	48 81 c4 18 01 00 00 	add    rsp,0x118
    32cd:	89 d0                	mov    eax,edx
    32cf:	5b                   	pop    rbx
    32d0:	5d                   	pop    rbp
    32d1:	c3                   	ret    
    32d2:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
    32d9:	00 00 00 
    32dc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
```

Ok, era difficile. Forse vedendo il codice sorgente sarà più ciaro? Eccolo:

```c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include "flag.h"

int slmain();

int main()
{

    char flag[255];
    int i = 0;
    int key;

    // Ignoro tutti i sengali ignorabili
    for (int i = 0; i < 100; i++)
      signal(i, SIG_IGN);

    // Niente ptrace
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return 1;
    }

    // Input chiave
    printf("Insert secret key: ");
    scanf("%d", &key);

    // solo per dare fastidio 
    slmain();

    // Decrypto la flag
    do {
        flag[i] = table[key].c;
        key = table[key].i;
    } while (flag[i++] != '{');

    // stampo la flag
    puts("Now we are decrypting your flag!");
    printf("CCIT");

    // i va a zero, è un operatore valido del C :)
    while (i --> 0) {
        putchar(flag[i]);
    }
    puts("");

    return 0;
}                                                                                                                                            ale@alerighi ~/git/CyberChallenge [master|✔]
```

Ovviamente non vi incollo qua tutto il contenuto di `flag.h` perché immaginerete sia enorme. Ecco le prime righe:

```c
// secret = 218113
struct { char c; int i; } table[] = {
{'{', 81837},
{'{', 964784},
{'7', 403991},
{'$', 823398},
{'>', 481794},
{'{', 953135},
{'q', 944024},
{'$', 301833},
```

Il codice completo (incluso lo script python per generarlo) lo trovate [qui](https://github.com/alerighi/CyberChallenge)

### Sì, ma come lo risolvevo?

Due modi. Il primo era quello di andare di bruteforce, generando tutte le possibili stringhe. Le chiavi possibili non sono molte, alla fine sono 100.000. Ovviamente prima andava tolto dall'eseguibile la chiamata al main di SL, ma era abbastanza facile.

Il secondo modo, più sofisticato, era rendersi conto di come è costruito l'algoritmo che decripta la chiave, e quindi riscrivere un programma in grado di fare la stessa cosa, assumendo che il primo carattere della flag è un `}`, l'ultimo `{` e tenendo conto che la flag ragionevolmente non è più lunga di 20/30 caratteri (altrimenti potrebbero esserci loop)




