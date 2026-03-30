# 🎯 Fawn — HackTheBox (Starting Point)

## Información General

| Campo | Detalle |
|-------|---------|
| **Plataforma** | HackTheBox — Starting Point |
| **Dificultad** | Muy Fácil |
| **OS** | Linux (Unix) |
| **Tags** | `ftp` `anonymous-login` `enumeration` `file-transfer` |

---

## Objetivo

Conectarse a un servidor FTP mediante acceso anónimo para descargar y leer la flag del sistema.

---

## Herramientas Utilizadas

- `ping` — verificación de conectividad con el objetivo
- `nmap` — enumeración de puertos y versiones de servicios
- `ftp` — cliente FTP para interactuar con el servidor

---

## Conceptos Clave

- **FTP** (File Transfer Protocol): protocolo de red para transferencia de archivos. Escucha por defecto en el **puerto TCP 21**.
- **SFTP** (SSH File Transfer Protocol): versión segura de FTP que cifra la comunicación.
- **Login anónimo**: característica de FTP que permite conectarse con el usuario `anonymous` y cualquier contraseña (generalmente un email), sin necesidad de cuenta válida.
- Código de respuesta **230**: "Login successful" — indica autenticación exitosa.
- Código de respuesta **331**: solicitud de contraseña.

---

## Metodología

### 1. Reconocimiento — Verificación de conectividad

```bash
ping 10.129.117.38
```

Se recibe respuesta ICMP, confirmando que el objetivo está activo y accesible.

---

### 2. Enumeración — Escaneo de puertos y versiones

```bash
nmap -sS -sV 10.129.117.38
```

**Resultado:**
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
Service Info: OS: Unix
```

El objetivo corre **vsftpd 3.0.3** en Linux/Unix. vsftpd (Very Secure FTP Daemon) es uno de los servidores FTP más comunes en sistemas Unix.

Para ver las opciones del cliente FTP:
```bash
ftp -h
```

---

### 3. Explotación — Acceso Anónimo FTP

Se conecta al servidor usando el usuario especial `anonymous`:

```bash
ftp 10.129.117.38
```

```
Name: anonymous
Password: [Enter — contraseña vacía]
230 Login successful.
```

Una vez dentro, se listan los archivos disponibles:

```bash
ftp> ls
  -rw-r--r--  1  0  0  32  Jun 04 2021  flag.txt
```

> **Nota:** `ls` y `dir` son ambos válidos para listar archivos en FTP. Sin embargo, `cat` no funciona en la shell FTP — es necesario descargar el archivo primero.

Se descarga el archivo con `get`:

```bash
ftp> get flag.txt
```

---

### 4. Captura de Flag

Tras salir del cliente FTP, se lee el archivo descargado localmente:

```bash
cat flag.txt
```

---

## Flags

| Tipo | Hash |
|------|------|
| **Root Flag** | `035db21c881520061c53e0536e44f815` |

---

## Lecciones Aprendidas

1. **FTP sin autenticación** (anonymous login habilitado) es una misconfiguration crítica. Nunca debe habilitarse en producción a menos que sea intencional y los archivos sean públicos.
2. **FTP transmite credenciales en texto plano** — incluso si no se usa anonymous, las contraseñas pueden ser capturadas con un sniffer. SFTP/FTPS son las alternativas seguras.
3. El escaneo de versiones con `-sV` de nmap es fundamental: conocer la versión exacta del servicio permite buscar vulnerabilidades conocidas (CVEs).
4. Siempre verificar conectividad con `ping` antes de proceder — si el objetivo no responde, los escaneos posteriores darán falsos negativos.
