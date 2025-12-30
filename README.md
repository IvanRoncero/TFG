# TFG – Proyecto CLI (última versión consolidada)

## Requisitos
- Python 3.10+
- Para cifrado real: `pip install cryptography`

## Estructura
- `tfg/` núcleo (modelos, enums, loader y APIs)
- `plugins/` plugins de exfil y crypto
- `tfg_cli.py` CLI principal

## Ejemplos HTTP (local)
Servidor:
```
py -3 tfg_cli.py receive --transfer-id RX1 --canal HTTP --metodo 1 --host 0.0.0.0 --puerto 8080 --ruta /upload --cifrado NINGUNO --plugins-dir plugins --out-file C:\ruta\salida.bin
```
Cliente:
```
py -3 tfg_cli.py send --transfer-id TX1 --canal HTTP --metodo 1 --host 127.0.0.1 --puerto 8080 --ruta /upload --recurso-tipo ARCHIVO --recurso-ubicacion C:\ruta\fichero.txt --fragment-size 1024 --cifrado NINGUNO --plugins-dir plugins
```

## Cifrado real
- Simétrico: `--cifrado SIMETRICO --algoritmo AESGCM --clave-privada C:\...\key.bin`
- Asimétrico: `--cifrado ASIMETRICO --algoritmo RSA_OAEP --clave-publica C:\...\pub.pem --clave-privada C:\...\priv.pem`
- Meta CRYPTO: `--crypto-meta-out meta.json` y `--crypto-meta-in meta.json`.
