# Voto Seguro Comunitario

Prototipo académico de votación cifrada con interfaz web local. **Solo datos ficticios.**

**Seguridad:** ECDH P-256 + HKDF · AES-256-GCM · Ed25519 · X.509 + HTTPS/TLS local · HMAC-SHA-256 · PBKDF2 (600 000 it.)

## Uso (Windows)
1. Instala Python 3.10+ y haz doble clic en `run.bat` (instala dependencias y abre http://127.0.0.1:8765).
2. Comité: crea la contraseña → Configuración → *Cargar ejemplo* → *Crear elección*.
3. Votantes: Inicio → Cabina del votante, con su ID y código.
4. Comité: Auditoría y Acta → *Cerrar elección y firmar acta*.

## Subir a GitHub
Doble clic en `subir_github.bat` (usa Git; con GitHub CLI crea el repo solo, si no, pide la URL de un repo vacío).

## Estructura
`core.py` criptografía · `server.py` servidor y API · `web/index.html` interfaz
