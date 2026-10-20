# Pwn — Calling Card

> The Crypt → Skeleton Key → Cursed Mirror → Your Library Card → Necromancy

Categoría: Pwn / Ingeniería inversa. Binarios ELF 64-bit servidos por red, presentados como el "calling card" de DEADFACE. Hilo técnico común: desbordamiento de pila, dificultad creciente: ret2win básico → ROP con argumentos → ROP + reutilización de código ofuscado del propio binario → ret2libc con PIE → SROP en binario freestanding.

**Método general seguido en toda la serie:** verificar SHA256 → `file`/`readelf`/`nm` → análisis de funciones (`objdump`/capstone, incluso en memoria desde el ZIP sin escribir a disco) → identificar el desbordamiento y su offset → elegir técnica según mitigaciones presentes → exploit con pwntools.

## Perfil de protecciones (checksec)

| Binario | Arch | RELRO | Canary | NX | PIE | Stripped |
|---|---|---|---|---|---|---|
| The_Crypt | amd64-64 | Partial | No | Enabled | No PIE (0x400000) | No |
| Skeleton_Key | amd64-64 | Partial | No | Enabled | No PIE (0x400000) | No |
| Cursed_Mirror | amd64-64 | Partial | No | Enabled | No PIE | No |
| Cursed_Library | amd64-64 | Partial | No | Enabled | **PIE** | No |
| Necromancy | amd64-64 | — | No | Enabled | No PIE | freestanding (sin libc/ld) |

## Stage 1 — The Crypt (puerto 5001) — XOR + ret2win

- Recon: ZIP de 513 MB con un ELF pequeño dentro; el resto, relleno aleatorio (entropía 8.0). Binario real ~20 KB.
- `de_crypt()` aplica XOR 0x13 sobre `nothing_at_all` → genera el código secreto; `main` lo compara con la entrada del usuario.
- Al acertar, `whispering_madness()` usa `gets()` sobre búfer de `0x40` → overflow. Existe `nowhere()` (0x401660) que imprime la flag y nadie la llama.
- Offset = 0x40 + 8 = 72.
- Gadgets: `0x401130` = `ret` (alineación), `0x401105` = `pop rsi; ret`.
- Exploit: relleno(72) + RET(alineación) + `nowhere()`.
- **Flag:** `deadface{d3crypt3d_1nt0_n0th1ng}`
- Aprendizaje: medir entropía delata relleno/señuelo; XOR simple es reversible; No PIE → ret2win directo.

## Stage 2 — Skeleton Key (puerto 5002) — ROP con argumentos

- Síntoma de ROP: símbolos `Wretched_Lock` y `gadgets` literal en el binario.
- `Wretched_Lock(x)` solo imprime la flag si `x == 0xdeadc0de`. Gadget `pop rdi; ret` = `0x401615`.
- Offset = 72 (mismo patrón `sub rsp,0x40` / `gets` / `leave;ret`).
- Exploit: relleno(72) + `pop rdi;ret` + `0xdeadc0de` + `Wretched_Lock` (`0x401507`).
- **Flag:** `deadface{R355UR3CT_D34D_C0D3}`
- Aprendizaje: pasar el primer argumento en RDI (ABI x86-64) encadenando gadgets.

## Stage 3 — Cursed Mirror (puerto 5003) — reutilizar código del reto

- Tema "espejo": cadenas en `.data` invertidas (`0x406188` = `hs/nib/` → al revés `/bin/sh`). El binario incluye `reflect()`, que invierte cadenas.
- Vuln: opción 2 del menú (`question()`) → `gets()` en `[rbp-0x40]` → offset 72.
- Exploit: `pop rdi;ret` + str7 + `reflect()` + `pop rdi;ret` + str7 + `system` — se usa el propio `reflect()` para convertir `/hs/nib/` en `/bin/sh` real en memoria, luego `system("/bin/sh")`.
- Resultado: shell (uid=1000 ubuntu) → flag en `secretflag.txt`.
- **Lección de oro:** al mezclar `gets`/`getchar` con `system("/bin/sh")`, los comandos enviados antes del exec se pierden en el buffer de stdin de libc — parece un "crash" fantasma. Hay que esperar (~1.5s) a que arranque el shell y enviar los comandos después.

## Stage 4 — Your Library Card (puerto 5004) — ret2libc con PIE

- El reto entrega `libc.so.6` (glibc 2.42, Debian) + `ld-linux-x86-64.so.2` → pista directa para ret2libc.
- Binario PIE; `checkout()` desborda con `gets()` → offset 104 (0x60 + 8).
- Dos fugas: `BookOfTheDead()` imprime su propia dirección con `%p` → fuga de PIE; `Necronomicon()` (nunca llamada) lee `puts@GOT` → fuga de libc, invocada por ROP.
- Offsets libc: `puts=0x82060`, `system=0x54790`, `"/bin/sh"=0x1aaea4`, `pop rdi;ret=0x2a9b7`.
- Exploit (3 interacciones por el bucle del menú): fuga PIE (`pie = leak − 0x1ba1`) → fuga libc (`libc_base = puts − 0x82060`) → `ret`(alineación) + `pop rdi;ret` + `"/bin/sh"` + `system` → shell → `cat Necronomicon.txt`.
- **Flag:** `deadface{T#3_L1br4ry_Kn0w5_A11}`
- Tropiezos: (1) no hace falta relleno extra por el `pop rbp` de una función — su propio `push rbp` al entrar ya lo cubre, la cadena es directa `[función][retorno]`; (2) el gadget `ret` de alineación debe estar en un segmento ejecutable `R-X` — uno en zona `R--` (datos) dio SIGSEGV silencioso; verificar siempre con `readelf -l`. (3) El binario usa `setvbuf(stdout, ..., _IONBF)`, por eso la salida aparece poco a poco.

## Stage 5 — Necromancy (reto final) — SROP

- ELF64 **freestanding**: sin libc ni enlazador dinámico, solo syscalls crudas; `.text` de apenas 120 bytes. No PIE, NX activo.
- Vuln: `read(0, buf, 0x400)` → overflow, offset = 256 (`0x100`).
- Función `reread`: `read(0, scratch, 0xf)` que deja `rax = 15` (número de syscall `rt_sigreturn`). Gadget `syscall_ret` en `0x401000` (`syscall; ret`).
- Sin gadgets `pop` disponibles → técnica: **SROP** (Sigreturn-Oriented Programming). Cadena: overflow → `reread` (deja `rax=15`) → `syscall` → `rt_sigreturn` → se entrega un `SigreturnFrame` falso con `rax=59` (`execve`), `rdi` apuntando a `/bin/sh` previamente escrito en memoria (`0x403b20`), `rsi=rdx=0` → shell.
- Detalle de envío: el overflow y los 15 bytes que alimentan `reread` se mandan en dos paquetes de red separados, para que el `read()` no los consuma de un solo golpe.
- Aprendizaje: un binario freestanding no se puede atacar con ret2libc (no hay libc que fugar); cuando no hay gadgets `pop` utilizables, SROP permite controlar todos los registros de golpe mediante un frame de señal falsificado.

## Habilidades demostradas

- Análisis de ELF: `readelf`, `nm`, `objdump`, y análisis en memoria con pyelftools + capstone (sin escribir a disco).
- Detección de mitigaciones (PIE, NX, canary, RELRO) y selección de la técnica de explotación adecuada según el perfil.
- Explotación de pila: cálculo de offsets (estático y, como método recomendado de confirmación, con `cyclic`/`cyclic_find`), ROP con argumentos, ret2libc con doble fuga, SROP.
- Depuración de fallos silenciosos: alineación de pila (`movaps`), gadgets ubicados en segmentos no ejecutables, buffering de stdin de libc al encadenar `system()`.
- Automatización de exploits con pwntools, incluyendo manejo de interacciones por red en servicios con menú/bucle.

## Balance / lecciones transversales

- Progresión de aprendizaje: ret2win básico → ROP con argumentos (ABI x86-64, primer argumento en RDI) → ROP + reutilización de código ofuscado del propio binario → ret2libc con PIE (doble fuga + offsets de la libc provista) → SROP en binario freestanding sin gadgets `pop`.
- Herramientas usadas en toda la serie: `file`, `readelf`, `nm`, `objdump -d -M intel`, cálculo de entropía con Python, pyelftools + capstone, pwntools.
- Lecciones:
  - Verificar siempre el SHA256 del archivo entregado.
  - La entropía delata relleno/señuelo en archivos sospechosamente grandes.
  - `gets()`/`read()` sin límite adecuado = overflow garantizado.
  - XOR simple es trivialmente reversible.
  - Sin PIE simplifica mucho la explotación (direcciones absolutas); con PIE hay que fugar la base del binario antes de construir la ROP chain.
  - Revisar los datos también "al revés" cuando el tema del reto lo sugiere.
  - Entender el buffering de stdin de libc es crítico al mezclar entrada por C con `system()`.
  - No asumir relleno extra por un `pop rbp`: si la función invocada hace su propio prólogo (`push rbp`), la cadena es directa `[función][retorno]`.
  - Un gadget `ret`/`pop` puede caer en una página sin permiso de ejecución (`R--`) — confirmar siempre con `readelf -l` el segmento antes de usarlo.
  - Cuando no hay gadgets `pop` disponibles (binarios freestanding, mínimos), SROP es la alternativa para controlar registros vía un frame de señal falsificado.
  - Dividir el envío de datos en paquetes separados cuando el programa hace varias llamadas a `read()`/`gets()` que podrían consumir de más si se manda todo junto.

---
[&larr; volver al índice](../README.md)
