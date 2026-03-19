# TFG — Paso M3 (CRYPTO plugins: simétrico y asimétrico)

Novedades:
- API de cifrado (`tfg/plugins/api_crypto.py`).
- Cargador ampliado (`tfg/plugins/loader.py`) para descubrir CRYPTO.
- Plugins de ejemplo: `plugins/crypto/symmetric_xor.py` (SIMÉTRICO XOR256 DEMO) y `plugins/crypto/asymmetric_fake.py` (ASIMÉTRICO DEMO).
- CLI `tfg_cli.py` integra cifrado/descifrado opcional en la tubería.

Descubrimiento:
py -3 tfg_cli.py scan-plugins --plugins-dir plugins

Envío (SIMÉTRICO XOR256):
py -3 tfg_cli.py send ^
  --transfer-id T3 ^
  --canal HTTP --metodo 1 --host example.com --puerto 443 ^
  --recurso-tipo ARCHIVO --recurso-ubicacion C:\ruta\fichero.txt --fragment-size 1024 ^
  --cifrado SIMETRICO --algoritmo XOR256 --clave-privada C:\ruta\clave_sim.bin ^
  --crypto-meta-out C:\ruta\meta.json ^
  --plugins-dir plugins

Recepción (SIMÉTRICO):
py -3 tfg_cli.py receive ^
  --transfer-id R3 ^
  --canal HTTP --metodo 1 --host example.com --puerto 443 ^
  --cifrado SIMETRICO --algoritmo XOR256 --clave-privada C:\ruta\clave_sim.bin ^
  --crypto-meta-in C:\ruta\meta.json --out-file C:\ruta\resultado.bin ^
  --plugins-dir plugins

Envío (ASIMÉTRICO DEMO):
py -3 tfg_cli.py send ^
  --transfer-id T4 ^
  --canal HTTP --metodo 1 --host example.com --puerto 443 ^
  --recurso-tipo ARCHIVO --recurso-ubicacion C:\ruta\fichero.txt ^
  --cifrado ASIMETRICO --algoritmo FAKE_RSA ^
  --clave-publica C:\ruta\pub.key --clave-privada C:\ruta\priv.key ^
  --crypto-meta-out C:\ruta\meta_rsa.json ^
  --plugins-dir plugins

Recepción (ASIMÉTRICO DEMO):
py -3 tfg_cli.py receive ^
  --transfer-id R4 ^
  --canal HTTP --metodo 1 --host example.com --puerto 443 ^
  --cifrado ASIMETRICO --algoritmo FAKE_RSA ^
  --clave-publica C:\ruta\pub.key --clave-privada C:\ruta\priv.key ^
  --crypto-meta-in C:\ruta\meta_rsa.json --out-file C:\ruta\resultado_rsa.bin ^
  --plugins-dir plugins

NOTA: Los plugins de cifrado de M3 son demostrativos (sin garantías criptográficas). En M6+ sustituir por AES-GCM/RSA-OAEP reales manteniendo interfaz.
