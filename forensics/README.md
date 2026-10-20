# Forensics — Tráfico de red y esteganografía EXIF

**En palabras simples:** "Forensics" es investigar evidencia digital después de que algo ya pasó — como un forense que examina la escena de un crimen, pero acá la escena es un archivo de tráfico de red capturado o un grupo de fotos. La idea es encontrar la "aguja en el pajar": entre miles de conexiones normales a internet, detectar las pocas que son sospechosas; o descubrir que una imagen que parece una foto común en realidad tiene un mensaje secreto escondido en sus datos internos (metadatos), invisible a simple vista.

Categoría: Forensics / Network. Dos retos independientes: exfiltración de datos robados disfrazada de tráfico web ordinario en una captura pcap, y un mensaje oculto repartido en los metadatos EXIF de 20 imágenes JPG "no relacionadas".

## Reto 1 — Tráfico: exfiltración HTTP (PCAP03.pcap)

- Artefacto: `PCAP03.pcap` — 62 KB, 348 frames, 100% HTTP. SHA256: `23cc1638bcdab5eca920a56605a3491933170e96187c2aae5356d7c6c99a78bc`
- Enunciado: un host comprometido envía datos robados "disfrazados de tráfico web ordinario".

### Enumeración
```bash
capinfos -c -u -a PCAP03.pcap
tshark -r PCAP03.pcap -q -z io,phs
tshark -r PCAP03.pcap -q -z conv,ip
tshark -r PCAP03.pcap -Y http -T fields -e http.host | sort | uniq -c | sort -rn
tshark -r PCAP03.pcap -Y http.request -T fields \
  -e ip.src -e ip.dst -e http.request.method -e http.host \
  -e http.request.uri -e http.user_agent -e http.content_type
```

### Hallazgo (anomalía)
- El host víctima `10.20.30.40` habla con decenas de IPs `93.184.x.x` (ruido web normal: wikipedia, youtube, nytimes, etc.).
- Único destino anómalo: `45.66.77.88` → `telemetry.deadface-cc.net`.
- 5 peticiones `POST /api/upload?seq=1..5`, todas con:
  - `Content-Type: application/octet-stream`
  - `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)` (UA minimalista, distinto del resto del tráfico)
  - Cabecera custom: `X-Session-Id: YnVzaW5lc3N9`

### Extracción
```bash
tcpdump -r PCAP03.pcap -A 'host 45.66.77.88'
printf 'YnVzaW5lc3N9' | base64 -d   # -> business}
printf 'ZGVhZGZhY2V7aHR0cF9leGZpbF9zbmVha3lfYnVzaW5lc3N9' | base64 -d
```

**Flag:** `deadface{http_exfil_sneaky_business}`

### Lección
- Contar destinos/hosts (`conv,ip` o `http.host` agrupado) delata al C2 entre el ruido de tráfico web legítimo.
- `Content-Type: application/octet-stream` + User-Agent atípico + cabecera HTTP custom es la firma típica de exfiltración disfrazada de tráfico web.
- El fragmento final de una flag puede estar escondido en una **cabecera HTTP**, no solo en el body.

## Reto 2 — Stego: 20 imágenes con datos en EXIF (exfiltration.zip)

- Artefacto: ZIP con 20 JPG (`image_01.jpg` … `image_20.jpg`), ~556 KB.
- Enunciado: imágenes "no relacionadas" esconden un mensaje para DEADFACE. Recuperarlo.

### Análisis
```bash
file image_*.jpg
exiftool image_01.jpg
```
Cada JPG tiene un `Image Unique ID` con forma `IMG_<hex>`, distinto por imagen.

### Reensamblado
El orden correcto lo da `DateTimeOriginal` (no el nombre de archivo):
```bash
for i in $(seq -w 1 20); do
  id=$(exiftool -s3 -ImageUniqueID image_$i.jpg | sed 's/^IMG_//')
  dt=$(exiftool -s3 -DateTimeOriginal image_$i.jpg)
  echo "$dt $id"
done | sort | awk '{printf "%s", $3}' | xxd -r -p
```

**Flag:** `deadface{timing-is-everything}`

### Lección
- No todo es LSB/steghide: el campo EXIF `ImageUniqueID` puede portar bytes de un mensaje.
- El orden de reensamblado puede depender de un metadato distinto al nombre de archivo.
- Los bytes reensamblados pueden venir como ASCII-hex — hay que decodificar hex antes de leer el resultado como texto.

## Lecciones transversales

- Para tráfico de red: contar destinos/conversaciones separa rápido el ruido de un único host/IP anómalo — ese es casi siempre el C2.
- Una cabecera HTTP custom puede llevar parte del secreto, igual que el body.
- Los metadatos EXIF van más allá de GPS/fecha: campos como `ImageUniqueID` pueden ser un canal de esteganografía de bytes crudos.
- Cuando un reto de reensamblado no especifica el orden por nombre de archivo, buscar otro metadato ordenable (timestamp, GPS, secuencia).

---
[&larr; volver al índice](../README.md)
