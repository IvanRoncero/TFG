# TFG — Paso M4 (Exfiltración HTTP real)

Plugins añadidos:
- `plugins/exfil/http_client_headers.py`  (método=1: datos en cabeceras)
- `plugins/exfil/http_client_verbs.py`    (método=2: alterna POST/PUT; datos en cuerpo)
- `plugins/exfil/http_server_common.py`   (infra compartida de servidor)
- `plugins/exfil/http_server_headers.py`  (método=1)
- `plugins/exfil/http_server_verbs.py`    (método=2)

## Uso rápido (local)

### 1) Recepción (servidor)
Terminal A:
```
py -3 tfg_cli.py receive ^
  --transfer-id RX1 ^
  --canal HTTP --metodo 1 ^
  --host 0.0.0.0 --puerto 8080 --ruta /upload ^
  --cifrado NINGUNO ^
  --plugins-dir plugins ^
  --out-file C:\ruta\salida.bin
```

### 2) Envío (cliente)
Terminal B:
```
py -3 tfg_cli.py send ^
  --transfer-id TX1 ^
  --canal HTTP --metodo 1 ^
  --host 127.0.0.1 --puerto 8080 --ruta /upload ^
  --recurso-tipo ARCHIVO --recurso-ubicacion C:\ruta\fichero.txt --fragment-size 1024 ^
  --cifrado NINGUNO ^
  --plugins-dir plugins
```

### Variante método=2 (verbs)
Usa `--metodo 2` en ambas terminales. El cliente alterna POST/PUT y el cierre se envía con HEAD.

## Notas
- Cliente sin dependencias: `urllib`. Servidor: `http.server`.
- Para cifrar, añade `--cifrado SIMETRICO --algoritmo AESGCM` (o `ASIMETRICO RSA_OAEP`) como en M3.
