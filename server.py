"""Voto Seguro Comunitario: servidor web local (interfaz + API) en 127.0.0.1.

Uso: py server.py  ->  abre http://127.0.0.1:8765
Solo práctica académica con datos ficticios.
"""
from __future__ import annotations

import hashlib, hmac, json, secrets, tempfile, threading, time, webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from core import (ElectionServer, LocalTLSServer, VoterWallet, VotingClient, b64, encrypt_roster,
                  json_bytes, make_admin_verifier, unb64, verify_admin_password)

ROOT, PORT = Path(__file__).resolve().parent, 8765
LOCAL = ("127.0.0.1", "localhost")


class State:
    def __init__(self) -> None:
        self.verifier = self.server = self.transport = self.client = self.tmp = self.last_env = None
        self.tokens: dict[str, float] = {}
        self.wallets: dict[str, VoterWallet] = {}
        self.hcodes: dict[str, str] = {}
        self.tries: dict[str, int] = {}
        self.logs: list[dict[str, str]] = []
        self.nfail, self.locked = 0, 0.0
        self.lock = threading.RLock()

    def log(self, msg: str, level: str = "info") -> None:
        self.logs = (self.logs + [{"t": datetime.now().strftime("%H:%M:%S"), "m": msg, "l": level}])[-200:]

    def stop(self) -> None:
        if self.transport: self.transport.close()
        if self.tmp: self.tmp.cleanup()
        self.transport = self.tmp = None


S = State()
ROUTES: dict[tuple[str, str], object] = {}


def route(method: str, path: str, admin: bool = False):
    def deco(fn):
        fn.admin = admin
        ROUTES[(method, path)] = fn
        return fn
    return deco


def need() -> ElectionServer:
    if not S.server:
        raise ValueError("Primero crea la elección en Configuración.")
    return S.server


@route("GET", "/api/state")
def state(_):
    e = S.server
    return {"admin_set": S.verifier is not None, "ready": e is not None, "open": bool(e and e.open),
            "org": e.organization if e else "", "candidates": e.candidates if e else [],
            "voters": len(S.wallets), "votes": len(e.ballots) if e else 0,
            "fingerprint": e.fingerprint if e else "",
            "minutes": {"acta": e.minutes, "firma": e.minutes_signature} if e and e.minutes else None}


@route("POST", "/api/login")
def login(b):
    pw = str(b.get("password", ""))
    if time.time() < S.locked:
        raise ValueError(f"Demasiados intentos. Espera {int(S.locked - time.time()) + 1} s.")
    if S.verifier is None:
        S.verifier = make_admin_verifier(pw)
        S.log("Contraseña del comité creada (PBKDF2-HMAC-SHA-256, 600 000 iteraciones).")
    elif not verify_admin_password(pw, S.verifier):
        S.nfail += 1
        if S.nfail >= 5:
            S.nfail, S.locked = 0, time.time() + 30
        S.log("Intento de acceso del comité fallido.", "warn")
        raise ValueError("Contraseña incorrecta.")
    S.nfail = 0
    token = secrets.token_urlsafe(24)
    S.tokens[token] = time.time() + 1800
    S.log("Sesión del comité iniciada.", "ok")
    return {"token": token}


@route("POST", "/api/election", admin=True)
def create(b):
    org = str(b.get("org", "")).strip()
    cands = [x.strip() for x in str(b.get("candidates", "")).splitlines() if x.strip()]
    if not org: raise ValueError("Escribe el nombre de la organización.")
    if len(cands) < 2 or len(set(cands)) != len(cands): raise ValueError("Ingresa dos o más candidaturas distintas.")
    if S.server and S.server.open and S.server.ballots:
        raise ValueError("Hay votos emitidos: cierra la elección antes de crear otra.")
    wallets, codes, rows = {}, {}, []
    for line in str(b.get("roster", "")).splitlines():
        if not line.strip(): continue
        p = [x.strip() for x in line.split(",", 1)]
        if len(p) != 2 or not all(p): raise ValueError(f"Formato incorrecto: {line}. Usa ID, Nombre.")
        if p[0] in wallets: raise ValueError(f"ID repetido: {p[0]}.")
        wallets[p[0]] = VoterWallet(p[0], ed25519.Ed25519PrivateKey.generate())
        codes[p[0]] = secrets.token_urlsafe(6)
        rows.append({"id": p[0], "nombre": p[1]})
    if not wallets: raise ValueError("Ingresa al menos un votante.")
    S.stop()
    S.tmp = tempfile.TemporaryDirectory(prefix=".voto_tls_", dir=ROOT)
    srv = ElectionServer(org, cands, {k: v.private_key.public_key() for k, v in wallets.items()})
    S.transport = LocalTLSServer(srv, Path(S.tmp.name))
    S.server, S.client = srv, VotingClient(S.transport, srv, srv.fingerprint)
    S.wallets, S.tries, S.last_env = wallets, {}, None
    S.hcodes = {k: hashlib.sha256(v.encode()).hexdigest() for k, v in codes.items()}
    encrypt_roster(rows)
    S.log(f"Elección creada para {org}. Padrón cifrado AES-256-GCM; carteras Ed25519 generadas.", "ok")
    S.log("Servidor HTTPS/TLS interno activo; huella X.509 fijada.", "ok")
    return {"codes": [{"id": r["id"], "name": r["nombre"], "code": codes[r["id"]]} for r in rows]}


@route("POST", "/api/vote")
def vote(b):
    e = S.server
    if not e or not e.open: raise ValueError("No hay una elección abierta.")
    vid, code, choice = (str(b.get(k, "")).strip() for k in ("voter_id", "code", "choice"))
    if S.tries.get(vid, 0) >= 5: raise ValueError("Identificador bloqueado por intentos fallidos. Contacta al comité.")
    h = S.hcodes.get(vid)
    if not h or not hmac.compare_digest(h, hashlib.sha256(code.encode()).hexdigest()):
        S.tries[vid] = S.tries.get(vid, 0) + 1
        S.log("Intento de identidad fallido en la cabina.", "warn")
        raise ValueError("Identificador o código incorrecto.")
    try:
        env, receipt = S.client.vote(S.wallets[vid], choice)
    except InvalidSignature as exc:
        raise ValueError("Firma inválida.") from exc
    S.last_env = env
    S.tries.pop(vid, None)
    S.log("Voto aceptado: ECDH + Ed25519 + AES-256-GCM sobre HTTPS/TLS.", "ok")
    return {"receipt": receipt}


@route("POST", "/api/cert", admin=True)
def cert(_):
    c = need().certificate
    c.public_key().verify(c.signature, c.tbs_certificate_bytes)
    d = "Certificado X.509 y huella fijada coinciden. Es autosellado (demo), no emitido por una CA pública."
    S.log(d, "ok")
    return {"detail": d}


@route("POST", "/api/audit", admin=True)
def audit(_):
    ok, d = need().audit()
    S.log(("AUDITORÍA OK: " if ok else "ALERTA: ") + d, "ok" if ok else "warn")
    return {"detail": d}


@route("POST", "/api/mitm", admin=True)
def mitm(_):
    e = need()
    try:
        VotingClient(S.transport, e, "00" * 32).vote(next(iter(S.wallets.values())), e.candidates[0])
    except ValueError as exc:
        S.log("MITM detectado: " + str(exc), "warn")
        return {"detail": "MITM detectado: " + str(exc)}
    raise ValueError("La simulación no fue detectada.")


@route("POST", "/api/tamper", admin=True)
def tamper(_):
    need()
    if not S.last_env: raise ValueError("Emite un voto antes de simular una alteración.")
    bad = dict(S.last_env, ciphertext_tag=b64(b"voto alterado"))
    try:
        S.client.post("/vote", bad)
    except ValueError as exc:
        S.log("ALTERACIÓN DETECTADA: " + str(exc), "warn")
        return {"detail": "Alteración detectada: " + str(exc)}
    raise ValueError("La alteración no fue detectada.")


@route("POST", "/api/close", admin=True)
def close(_):
    e = need()
    if not e.open: raise ValueError("La elección ya está cerrada.")
    m, sig = e.close_and_sign()
    e.certificate.public_key().verify(unb64(sig), json_bytes(m))
    S.log("Elección cerrada; acta firmada Ed25519 y verificada.", "ok")
    return {"ok": True}


@route("GET", "/api/logs", admin=True)
def logs(_):
    return {"logs": S.logs[-100:]}


@route("POST", "/api/logout", admin=True)
def logout(_):
    return {"ok": True}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code: int, body, ctype: str = "application/json; charset=utf-8") -> None:
        data = body if isinstance(body, bytes) else json_bytes(body)
        self.send_response(code)
        for k, v in (("Content-Type", ctype), ("Content-Length", str(len(data))), ("Cache-Control", "no-store"),
                     ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
                     ("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _trusted(self) -> bool:
        origin = self.headers.get("Origin")
        host_ok = self.headers.get("Host", "").split(":")[0] in LOCAL
        return host_ok and (not origin or origin.split("//")[-1].split(":")[0] in LOCAL)

    def _handle(self, method: str) -> None:
        if not self._trusted(): return self._send(403, {"error": "Origen no permitido."})
        path = self.path.split("?")[0]
        if method == "GET" and path == "/":
            return self._send(200, (ROOT / "web" / "index.html").read_bytes(), "text/html; charset=utf-8")
        fn = ROUTES.get((method, path))
        if not fn: return self._send(404, {"error": "No encontrado."})
        try:
            if fn.admin:
                tok = self.headers.get("X-Token", "")
                if S.tokens.get(tok, 0) < time.time(): return self._send(401, {"error": "Sesión del comité requerida."})
                if path == "/api/logout": S.tokens.pop(tok, None)
            n = int(self.headers.get("Content-Length") or 0)
            if n > 64_000: raise ValueError("Solicitud demasiado grande.")
            body = json.loads(self.rfile.read(n) or b"{}") if method == "POST" else {}
            with S.lock:
                out = fn(body)
            self._send(200, out)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})

    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")


def main() -> None:
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    httpd.daemon_threads = True
    url = f"http://127.0.0.1:{PORT}"
    print(f"Voto Seguro Comunitario en {url}  (Ctrl+C para salir)")
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        S.stop()


if __name__ == "__main__":
    main()
