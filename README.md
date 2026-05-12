![Cybersecurity](https://img.shields.io/badge/Focus-Offensive%20Security-red)
![Python](https://img.shields.io/badge/Python-3.12-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Lab%20Repository-informational)

# BreachCraft

BreachCraft es un laboratorio de seguridad ofensiva y automatización enfocado en
entornos controlados como HackTheBox, TryHackMe y laboratorios propios. El
repositorio combina writeups técnicos con herramientas en Python para practicar
reconocimiento, análisis de escaneos y revisión de logs.

> Uso exclusivamente educativo y de investigación ética. Ejecuta las técnicas y
> herramientas de este repositorio solo contra sistemas propios o con autorización
> explícita.

## Contenido del Repositorio

```text
BreachCraft/
|-- README.md
|-- LICENSE
|-- Writeups/
|   |-- 01_appointment_sql_injection.md
|   |-- 02_dancing_smb.md
|   |-- 03_fawn_ftp.md
|   |-- 04_mysql.md
|   |-- 05_redeemer_redis.md
|   `-- 06_wing_data.md
`-- Scripts/
    |-- scanner.py
    |-- recon.py
    |-- parse_scan.py
    |-- auth_analysis.py
    |-- log_analysis.py
    |-- tests/
    |-- pyproject.toml
    `-- uv.lock
```

## Writeups

| Archivo | Tema principal | Plataforma |
| --- | --- | --- |
| `01_appointment_sql_injection.md` | SQL Injection y bypass de autenticación | HackTheBox Starting Point |
| `02_dancing_smb.md` | Enumeración SMB y acceso anónimo | HackTheBox Starting Point |
| `03_fawn_ftp.md` | FTP anónimo y transferencia de archivos | HackTheBox Starting Point |
| `04_mysql.md` | MariaDB expuesto con credenciales débiles | HackTheBox Starting Point |
| `05_redeemer_redis.md` | Redis sin autenticación y enumeración de claves | HackTheBox Starting Point |
| `06_wing_data.md` | RCE, vhosts, cracking de hashes, SSH y escalación de privilegios | HackTheBox |

## Automatización en Python

Los scripts viven en `Scripts/` y están orientados a tareas repetibles de
laboratorio:

| Script | Propósito |
| --- | --- |
| `scanner.py` | Escáner TCP concurrente con salida JSON. |
| `recon.py` | Reconocimiento integrado para dominios e IPs; genera `results.json`, `report.md` y `audit.log`. |
| `parse_scan.py` | Parser de XML de `nmap` con enriquecimiento opcional de claves SSH mediante `ssh-keyscan`. |
| `auth_analysis.py` | Análisis de logs `sshd` para intentos fallidos, usuarios atacados y relación fallo/éxito. |
| `log_analysis.py` | Análisis de access logs web para SQLi, path traversal, XSS, command injection, probes de WordPress y anomalías horarias. |

`Scripts/tests/` contiene pruebas unitarias con `pytest`.
`Scripts/sample_output/` conserva salidas de ejemplo intencionales. Las salidas
generadas fuera de esa carpeta, archivos JSON temporales y PDFs locales quedan
fuera de Git para mantener el repositorio limpio.

## Requisitos

- Python `3.12` o superior.
- `uv` para instalar dependencias y ejecutar comandos reproducibles.
- Herramientas externas según el flujo: `nmap`, `dig`, `whois`, `curl` y
  `ssh-keyscan`.
- Herramientas de laboratorio usadas en los writeups: `gobuster`, `smbclient`,
  `ftp`, `mysql`, `redis-cli`, `hashcat` y Metasploit, según corresponda.

## Instalación

```bash
cd Scripts
uv sync
```

## Uso Rápido

```bash
# Escaneo TCP básico
uv run python scanner.py 127.0.0.1 --ports 22,80,443 --output scan_results.json

# Reconocimiento integrado de un dominio autorizado
uv run python recon.py example.com --mode domain --output recon_example

# Reconocimiento integrado de una IP autorizada
uv run python recon.py 127.0.0.1 --mode ip --output recon_local

# Parseo de salida XML de nmap
uv run python parse_scan.py --input scan.xml --output hosts.json

# Análisis de logs de autenticación SSH
uv run python auth_analysis.py --input auth.log --output auth_summary.json

# Análisis de logs web con reporte Markdown
uv run python log_analysis.py --input access.log --output web_analysis.json --report web_report.md
```

## Calidad y Pruebas

```bash
cd Scripts
uv run pytest
uv run ruff check .
```

## Preparación Antes de Subir

El repositorio está configurado para subir solo contenido útil: código fuente,
tests, writeups, lockfile, licencia y `Scripts/sample_output/` como evidencia de
ejemplo. La configuración excluye caches, entornos virtuales, logs, salidas
locales de escaneo, JSON generados fuera de `sample_output/`, PDFs locales,
metadatos de agentes y material auxiliar no destinado a publicación.

Revisión recomendada antes de publicar:

```bash
git status --short --ignored
git add README.md .gitignore LICENSE Writeups Scripts
git status --short
```

## Ética y Alcance Legal

El autor no se hace responsable por el mal uso de la información o herramientas
contenidas en este repositorio. El acceso a sistemas sin autorización previa es
ilegal. Todas las pruebas documentadas deben ejecutarse en CTFs, laboratorios
propios o plataformas con consentimiento explícito.
