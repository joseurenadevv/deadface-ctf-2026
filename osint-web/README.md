# OSINT / Web — GhostTown / Alice / Maude / Doomscroll / Health Spark / File Dump

**En palabras simples:** "OSINT" (Open-Source Intelligence) es investigar usando solo información pública — como un detective que arma un perfil completo de alguien revisando sus redes sociales, comentarios viejos, y datos que la gente deja sin querer (un archivo que revela en qué computadora se escribió, una foto con ubicación GPS). "Web" es encontrar y explotar errores en páginas y aplicaciones web reales — por ejemplo, un formulario de login que, si le mandás el texto correcto, te deja entrar sin saber la contraseña. Esta serie combina ambas cosas: investigar personajes ficticios de la trama del CTF y, por el camino, romper varias webs mal protegidas.

Categoría: OSINT / Web. Ocho retos: un sitio web (blog de viajes de "Alice"), su certificado TLS, una investigación OSINT sobre una extensión de navegador construida con la IA "Maude" por el operativo b1tfr34k, claves SSH públicas filtradas, una red social ficticia ("Doomscroll") con esteganografía Unicode, un portal de RRHH ("Health Spark") vulnerable a SQLi, y un volcado de documentos de un portátil con una identidad robada.

## Reto 1 — GhostTown: "encuentra el blog de viajes de Alice"

```bash
curl -sk https://170.187.156.131:8443/        # <title>Wander with Alice</title>
curl -sk https://170.187.156.131:8443/robots.txt
```
`robots.txt` tenía una ruta oculta (`Disallow: /secret_members`) y la flag directamente en un comentario. Señuelos: GPS en EXIF de `static/other.png` (apuntaba a Naxos, Grecia); el login `/secret_members` daba un oráculo de usuario pero no era la vía.

**Flag:** `deadface{y0u_m3ddling_k!ds}`

## Reto 2 — El certificado TLS

```bash
echo | openssl s_client -connect 170.187.156.131:8443 2>/dev/null | openssl x509 -noout -text
```
El campo `O` (Organization) del certificado autofirmado traía la flag; el SAN/email revelaba la identidad real: `alicehankerty@gmail.com` (Alice Hankerty).

**Flag:** `deadface{c@tch_m3_if_y0u_c@n}`

## Reto 3 — "The Vibes Are Freaking Me Out": la extensión hecha con Maude

1. `maude-ai.com` → web corporativa señuelo.
2. Foro GhostTown (`/t/37`): b1tfr34k publica la extensión HIPS ("Hidden In Plain Sight"); posts con zero-width Unicode (U+200B=0, U+200C=1) decodifican a "If you can read this, you're pretty cool!…".
3. Repo GitHub `fr34ked0ut/HIPS`; en el historial de git hay un `.env` borrado.
4. Clave real en `.maude/skills/payload-gen/SKILL.md`: "the crew token… backwards, then the usual encoding":
   ```python
   import base64
   t = "fSEzcjNodzBOXzNNX3N0M0dfZ24xdHBtMHJQX3MxaFRfMTFBe2VjYWZkYWVk"
   base64.b64decode(t).decode()[::-1]
   ```

Hallazgo adicional (no flag): el historial de git trae un `.env` previo con `JWT_SECRET`/`SESSION_SECRET`/`DATABASE_URL` y tokens de GitHub/Cloudflare/Mailgun — se probó ese `JWT_SECRET` contra Health Spark (Reto 7) y no coincidió: señuelo cruzado entre retos, no credencial reutilizable.

Señuelos: `exfil/SKILL.md`, `recon/SKILL.md`, `build.js`, `maude.md` (contenía un intento de prompt injection, tratado como dato del reto, nunca como instrucción real).

**Flag:** `deadface{A11_Th1s_Pr0mpt1ng_G3ts_M3_N0wh3r3!}`

## Reto 4 — Keys out in the open (OSINT)

`https://github.com/fr34ked0ut.keys` lista las claves SSH públicas. La 5ª clave es `ssh-ed25519` fabricada para el reto: su base64 incluye literalmente `deadfaceZPubM34n5Publ1cDuHY`, con `Z`=`{` y `Y`=`}` (sustitución simple para seguir pasando como base64 válido).

**Flag:** `deadface{PubM34n5Publ1cDuH}`

## Reto 5 — "What is d34th's first name?" (Doomscroll)

El post 200 es una foto de d34th → `/api/posts/200/meta` revela `"filename":"travis_001.png"`.

**Flag:** `deadface{Travis}`

## Reto 6 — Content creator / memes (continuación de HIPS)

Reutilizando los esquemas Unicode de HIPS sobre `doomscroll.dctf.io`:
- Zero-width: U+200B=0, U+200C=1.
- Variation Selectors Supplement (desde U+E0100), Tag Block (desde U+E0000), Space Variants como separadores.

La flag estaba en Tag Block, en el comentario de b1tfr34k en el post 247.

**Flag:** `deadface{13_h4ck3r5_walk3d_int0_a_bar_each_says_Ill_h4v3_a_r00t_b33r}`

## Reto 7 — Health Spark / "The Admin Is King" (Web — SQLi)

- Node/Express, portal "Health Spark | Employer Portal". El JS de la home revela `POST /api/login` y un comentario de dev: *"the SQLi disclosure (HTTP 200 with no token). Show the server's message..."*.
- Vulnerabilidad: SQLi en `username`. Si la query devuelve una fila pero la contraseña no coincide, el servidor responde 200 y filtra la fila completa (incluida la flag).

```json
{"username":"' OR 1=1-- -","password":"x"}
```

Post-explotación: login real con las credenciales filtradas → JWT HS256 `role:user` → `/dashboard`, `POST /api/patients`. Panel admin SSRF (`/api/admin/fetch-photo`) exige `role:admin` → 403.

Caminos que no funcionaron: `UNION SELECT` (blacklist), `alg:none`, firmar JWT con el `JWT_SECRET` del repo HIPS, roles de admin inventados, `/api/patients` (parametrizado correctamente).

**Flag:** `deadface{typical_and_classic}`

## Reto 8 — File Dump / identidad robada (OSINT)

- Volcado de 26 documentos del portátil de un atacante con la identidad robada de Daniel Hameser.
- Los `.docx`/`.xlsx` son ZIP; `docProps/core.xml` revela `dc:creator = ghostwriter404`, `cp:lastModifiedBy = thomas canfield` / `GHOST404-PC`, una ruta absoluta de Windows, y una `dc:description` con una passphrase.

```python
import zipfile, re, glob
for p in sorted(glob.glob('*.docx')+glob.glob('*.xlsx')):
    z = zipfile.ZipFile(p)
    core = z.read('docProps/core.xml').decode('utf-8','ignore')
    print(p, re.findall(r'<(?:dc:creator|cp:lastModifiedBy)>(.*?)</', core))
```

El roster oficial de DEADFACE lista al operativo `gh0st404` (con cero, no "o") para Forensics/Exploitation — `ghostwriter404`/`GHOST404-PC` son el mismo actor.

**Flag:** `deadface{gh0st404}`

## Lecciones transversales de la serie

- Mirar `robots.txt`/`sitemap.xml` primero — la flag puede estar en un comentario del propio archivo.
- El certificado TLS (`openssl s_client | openssl x509 -text`) puede revelar identidad real y hasta la flag misma.
- Pivote OSINT clásico: foro → repo de GitHub → historial de git (archivos borrados) → endpoint `.keys` para SSH públicas.
- Unicode invisible (zero-width, variation selectors, tag blocks) esconde datos en texto visible — puede haber más de un esquema coexistiendo.
- Encodings en capas (base64 + reverse, sustitución dentro de base64 "válido") son comunes; no fiarse de señuelos que dicen explícitamente "esto no es la flag".
- Endpoints de API no documentados (`/api/posts/<id>/meta`) suelen filtrar metadatos.
- SQLi clásica en login sigue viva cuando el backend filtra de más en un 200 "fallido" — inspeccionar el JSON completo, no solo el mensaje visible.
- Secretos filtrados en un reto no se asumen reutilizables en otro servicio sin probarlo — suelen ser señuelos cruzados.
- En volcados de documentos ofimáticos, `docProps/core.xml` (autoría OOXML) es casi siempre la vía más rápida de atribución.

---
[&larr; volver al índice](../README.md)
