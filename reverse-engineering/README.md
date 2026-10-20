# Reverse Engineering — Cereal Killer / Spooky Cereals / iOS

Categoría: Reverse Engineering. Serie de crackmes "Spooky Cereals" / "Cereal Killer" (binarios de distintas plataformas) más retos independientes ("It But A Wee Bit Reverse" / re02, "Keypad-Oracle" / iOS, "Aurora Patient Portal" / iOS app con 4 tareas). Cada reto entrega un binario a analizar; hay que recuperar un password (en la serie Cereal Killer, siempre el cereal favorito de la especie alien del reto) y, a menudo, una flag escondida tras chequeos internos.

**Herramientas usadas en la serie:** `file`, `nm`, `readelf`, `objdump`, `r2`, `rabin2`, `strings`, `gdb`, `7z`, `unzip`, `john` (+ rockyou), `curl`, capstone, Python 3, `openssl`, `exiftool`, `sqlite3`, `plutil`/`plistlib`.

## Keypad-Oracle — app iOS/Swift, PIN de 4 dígitos

- App iOS ("teclado oráculo") que pide un PIN de 4 dígitos sin repetir y cifra ese PIN mostrando un hex en pantalla. Toda la lógica está en `Keypad-Oracle.debug.dylib` (arm64, Swift); el `binarySalt` está elegido para que **solo el PIN correcto** produzca un texto legible (la flag). No hay comparador ni literal `deadface` en el binario — la flag **emerge** del algoritmo.
- SHA256: `7bfda8f6fa3bebbe29a6e18c4312a29ec9a3cdfda394eb01d39a59df849af49e`
- Bundle id: `com.deadface.keypadoracle.rickS` — Arch: arm64 (iPhoneSimulator)

### Algoritmo (`encode`)
1. `loadSeedTable()` lee `KeypadConfig.json` y `hexDecodedBytes` convierte cada valor → 27 bytes.
2. `encode(pin:)` exige 4 dígitos sin repetir y para cada posición `i` acumula `derive(seedTable[pin[i]], pin[i], i)` con XOR.
3. Final: `hex( XOR_{i=0..3} derive(...) XOR binarySalt )`.

```python
def rotl8(x, n):
    n %= 8
    return ((x << n) | (x >> (8 - n))) & 0xff

def derive(seed, digit, position):
    out = []
    for i, b in enumerate(seed):
        x  = b ^ ((33*(position+1)) & 0xff) ^ ((19*digit) & 0xff) ^ ((7*i) & 0xff)
        x  = rotl8(x, (digit + position + i) % 8)
        x ^= (i + digit + 11*position) & 0xff
        out.append(x)
    return out
```

Se enumeran las **5040 permutaciones** de 4 dígitos distintos; exactamente una produce bytes imprimibles con formato de flag — un "oráculo por imprimibilidad", no por comparación directa.

- **PIN correcto:** `3 7 1 9`
- **Flag:** `deadface{your-pin-is-valid}`

### Aprendizajes
- En apps iOS/Swift la lógica suele estar en `*.debug.dylib`, no en el Mach-O principal; los símbolos mangled de Swift son prácticamente autodocumentados.
- Cuando el espacio de búsqueda es chico, no hace falta invertir el algoritmo analíticamente: se enumera por fuerza bruta y se elige la única salida con sentido.

## Aurora Patient Portal — app iOS, 4 tareas encadenadas

- `.ipa` de 2.5 MB. Bundle: `RAJNB.Aurora-Health-Mobile`. Todo resuelto con herramientas estáticas de inspección: `strings`, `exiftool`, `sqlite3`, `plistlib` — sin emulador ni debugger.

### Tarea 1 — Info Leaks: nombre y DOB del paciente
`Info.plist` contiene `AuroraPatientBootstrap` en base64:
```bash
printf 'eyJwYXRpZW50TmFtZSI6Ik1hcmEgVm9zcyIsImRhdGVPZkJpcnRoIjoiMTk4OC0wNC0xNyIsImNsaW5pYyI6Ildlc3RsYWtlIn0=' | base64 -d
# {"patientName":"Mara Voss","dateOfBirth":"1988-04-17","clinic":"Westlake"}
```
`aurora_chest_xray.jpg` referencia `PID-847261` = `pid` máximo de la BD → el paciente activo del reto.
- **Flag:** `deadface{mara-voss-1988-04-17}`

### Tarea 2 — Down the Rabbit Hole: Patient ID
Metadatos XMP de `aurora_chest_xray.jpg`:
```bash
exiftool -a -G1 -s aurora_chest_xray.jpg | grep -i identifier
# [XMP-dc] Identifier : PID-847261
```
- **Flag:** `deadface{847261}`

### Tarea 3 — Medicamentos del paciente actual
```bash
sqlite3 -header -column aurora_meds.sqlite "SELECT * FROM medications WHERE pid=847261;"
```
- **Flag:** `deadface{Candesartan}`

### Tarea 4 — Gateway server
```bash
strings -a "Aurora Health Mobile" | grep -aiE "gw-|gateway|westlake|Last Gateway Check"
# gw-westlake-int-03
```
- **Flag:** `deadface{gw-westlake-int-03}`

### Lección Aurora
- Un `.ipa` es literalmente un ZIP: `Info.plist` puede traer un "bootstrap" en base64 con datos sensibles sin tocar el binario.
- Datos "escondidos" pueden estar en metadatos XMP/EXIF de una imagen del bundle, no en el binario.
- Una BD SQLite embebida permite correlacionar paciente ↔ medicación ↔ imagen entre varios ficheros.
- El binario Swift/SwiftUI tiene símbolos y strings autoexplicativos, recuperables con `strings -a` sin desensamblar.

## It But A Wee Bit Reverse — "Guarding something" (re02.bin, 15 pts)

- ELF64 x86-64, PIE, **no strippeado**. SHA256: `fa76583b6f4c9f6414fb79c3ffe717709ba3d74ce62ce7043d59807e8ca538f8`
- Símbolos: `pw_enc` (`0x4010`, 10 bytes), `flag_enc` (`0x4020`, 31 bytes). Sin cadenas útiles en claro.
- Verificación: `cmp (input[i] ^ 0x42), pw_enc[i]`. Si pasa, imprime `flag_enc[i] ^ input[i % 10]`.

```python
enc_pw = bytes.fromhex("31372c312a2b2c277670")
pw = bytes(c ^ 0x42 for c in enc_pw)              # b"sunshine42"
enc_flag = bytes.fromhex("17100f170e080d004f4a430731421b36000a406d161b0d0111191a0c5b5c0e")
flag = bytes(enc_flag[i] ^ pw[i % len(pw)] for i in range(len(enc_flag)))
print(flag.decode())
```
- **Password:** `sunshine42`
- **Flag:** `deadface{x0r_1s_not_encryption}`

## Cereal Killer 01 — "Insectoids / Cookie Crisp" (re01-lin-x86.bin, 50 pts)

- ELF 32-bit, **PIE, no stripped**. Símbolos: `base64_decode`, `SHA1*`, `RC4/KSA/PRGA`.
- `main`: `base64_decode(ENCODED_HASH)` → SHA1 objetivo; `SHA1(input) == objetivo` → `base64_decode(blob)` → `RC4(password, blob)` → URL.
- El string `base64_UTF16` no es dato cifrado: es la **tabla de alfabeto** de un Base64 permutado (confirmado con breakpoint en `gdb`, no reconstruido a mano).
- Crack offline del SHA1 con `john --format=raw-sha1 --wordlist=rockyou.txt`:
- **Password:** `cookiecrisp` (cereal favorito de los Insectoids)
- URL final: `https://cerealkiller.lyttonlabs.org/unwanted-guests/ick.png` (flag en texto dentro del PNG)

## Cereal Killer 02 — "Nordics / Frankenberry" (re03, 150 pts)

- `.7z` (password `KlippyAI`) con ELF + PE + un `.exe` .NET señuelo ("entrenado con IA", se ignora).
- `main`: XOR de dos bloques de 256 B de `.rodata` buscando el marcador `badf00d`. El XOR directo da basura → pista "**TIME is REVERSIBLE**" = la key está invertida: `plaintext[i] = A[i] ^ B[255-i]`.

```python
A = lin[0x2a20:0x2a20+0x100]; B = lin[0x2b24:0x2b24+0x100]
out = bytes(a ^ b for a,b in zip(A, B[::-1]))
clean = out.translate(None, b' .*\n')
```
- **Flag:** `deadface{N0rdics-R3ally-like-Frank3nb3rry-cuz-bro-is-tall-like-they-are!}`

## Cereal Killer 03 — "Reptilians / Lizard People" (re04-win-x64.exe, 500 pts)

- Reto multi-etapa: check de password (MD5) + flag cifrada + **anti-debug**.
- `main` compara `MD5(password)` contra un digest embebido → crack offline con `rockyou.txt` → **`letmein`**.
- Anti-debug: un VEH + hardware breakpoint (Dr0/Dr7) redirige a "Access denied" en runtime aunque el password sea correcto — la flag **nunca se imprime en vivo**. Hay que descifrarla estáticamente: `MD5(password)[:8]` como semilla de un keystream `xorshift64` que descifra 55 bytes de ciphertext.

```python
seed = int.from_bytes(pass_md5[:8], "little") ^ 0xd1cefa11badc0de5
# xorshift64: x ^= x<<13; x ^= x>>7; x ^= x<<17  →  byte = x & 0xff
```
- **Flag:** `deadface{Liz4rds_L0ve_Krampuffs_for_some_odd_reason...}` (verificada contra un segundo MD5 embebido en el binario)

## Cereal Killer 04 — "Greys" (re05.exe, 250 pts)

- Loader .NET de dos etapas: blob XOR de 2 bytes (`0x41 0x33`) en `.sdata` descifra un segundo ensamblado (empieza con `MZ`).
- `MyClass.Run()`: compara `MD5(password) == MD5("booberry")`; `password2 = input+input`; `DecryptAES()` usa AES-256-CBC con clave vía `Rfc2898DeriveBytes` (PBKDF2-HMAC-SHA1, salt=IV=`"thegreysarecomin"`, 1000 iteraciones).
- **Cereal/password:** `booberry` | **Flag:** `deadface{Before_Consenting_to_Med_Exam_Ascertain_Destination_of_Finger!}`

## Lecciones transversales de la serie RE

- "Strings won't save you": un binario no strippeado delata su estructura por los **nombres de símbolos**, aunque no tenga strings legibles. Vale también para `.dylib` de Swift.
- Espacio de búsqueda chico (ej. 5040 permutaciones) → fuerza bruta + filtro por "salida con sentido" en vez de invertir el algoritmo.
- XOR de un solo byte = clave trivialmente recuperable; si la password cifra la flag con el mismo esquema, el mismo paso que verifica también descifra.
- Ante varios binarios con la misma lógica, atacar siempre el **ELF no-stripped** primero; ignorar el ejecutable ".NET entrenado con IA" como señuelo temático.
- `nm`/`readelf`/`rabin2 -zz` delatan la criptografía usada (SHA1, RC4, MD5) antes de desensamblar nada.
- El password del reto siempre es el cereal favorito de la especie alien; cuando sale de un hash, es preimagen → crack offline con wordlist, nunca fuerza bruta online.
- Un string "tipo Base64" puede ser la tabla de alfabeto de un decodificador custom — confirmar con breakpoint en vivo, no a mano.
- Las pistas narrativas del enunciado ("TIME is REVERSIBLE") suelen ser instrucciones literales de criptografía.
- Constantes `0x67452301/0xefcdab89/0x98badcfe/0x10325476` = firma de MD5.
- Un binario que nunca imprime la flag en runtime puede tener anti-debug (VEH + Dr0/Dr7) → atacar estáticamente, reversando la rutina de descifrado en Python.
- `Rfc2898DeriveBytes` en C# = PBKDF2-HMAC-SHA1; AES-CBC+PKCS7 se descifra con `openssl enc -d`.
- En una app iOS entregada como `.ipa`, revisar primero `Info.plist` y metadatos XMP/EXIF antes de desensamblar el Mach-O — a veces toda la cadena se resuelve sin tocar código máquina.

---
[&larr; volver al índice](../README.md)
