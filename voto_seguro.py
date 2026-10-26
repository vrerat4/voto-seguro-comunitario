"""Voto Seguro: prototipo académico de votación cifrada (un solo archivo).

Ejecuta:  py voto_seguro.py   (instala PySide6 y cryptography la primera vez)
Cripto: ECDH P-256 + HKDF · AES-256-GCM · Ed25519 · X.509 + HTTPS/TLS local · HMAC · PBKDF2.
Solo para práctica con datos ficticios; no es un sistema electoral real.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import time

_need = [p for p in ("PySide6", "cryptography") if importlib.util.find_spec(p) is None]
if _need:
    print("Instalando:", *_need)
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", *_need])

import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import ssl
import tempfile
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ELECTION_ID = "ELECCION-COMUNITARIA-2026"
AAD_VOTE = b"votacion-comunitaria|v1"

def json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)

def derive_key(shared: bytes, server_nonce: bytes, client_nonce: bytes, session_id: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=server_nonce + client_nonce,
                info=b"UCV|ECDH|AES-256-GCM|" + session_id.encode("ascii")).derive(shared)

def make_admin_verifier(password: str) -> dict[str, str | int]:
    if len(password) < 10:
        raise ValueError("La contraseña del comité debe tener al menos 10 caracteres.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
    return {"salt": b64(salt), "verifier": b64(digest), "iterations": 600_000}

def verify_admin_password(password: str, verifier: dict[str, str | int]) -> bool:
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), unb64(str(verifier["salt"])),
        int(verifier["iterations"]))
    return hmac.compare_digest(digest, unb64(str(verifier["verifier"])))

def encrypt_roster(rows: list[dict[str, str]]) -> tuple[bytes, bytes]:
    key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    return nonce, AESGCM(key).encrypt(nonce, json_bytes(rows), b"padron|v1")

@dataclass
class VoterWallet:
    voter_id: str
    private_key: ed25519.Ed25519PrivateKey

@dataclass
class Pending:
    private_key: ec.EllipticCurvePrivateKey
    client_public: str
    server_nonce: str
    voter_id: str

class ElectionServer:
    """Lado servidor: identidad X.509, handshake ECDH y validación del sufragio."""
    def __init__(self, organization: str, candidates: list[str],
                 voters: dict[str, ed25519.Ed25519PublicKey]) -> None:
        self.organization, self.candidates, self.voters = organization, candidates, voters
        self.signing_key = ed25519.Ed25519PrivateKey.generate()
        self.certificate = self._certificate(organization)
        self.certificate_pem = self.certificate.public_bytes(serialization.Encoding.PEM)
        self.fingerprint = self.certificate.fingerprint(hashes.SHA256()).hex()
        self.pending: dict[str, Pending] = {}
        self.used: set[str] = set()
        self.ballots: list[dict[str, str]] = []
        self.results = {candidate: 0 for candidate in candidates}
        self.audit_key = secrets.token_bytes(32)
        self.open = True
        self.minutes: dict[str, Any] | None = None
        self.minutes_signature: str | None = None

    def _certificate(self, organization: str) -> x509.Certificate:
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization[:64]),
            x509.NameAttribute(NameOID.COMMON_NAME, "Servidor Electoral Local"),
        ])
        now = datetime.now(timezone.utc)
        return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(self.signing_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=7))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.SubjectAlternativeName([
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(self.signing_key, algorithm=None))

    def handshake(self, request: dict[str, str]) -> dict[str, str]:
        voter_id = request["voter_id"]
        if voter_id not in self.voters:
            raise ValueError("Identidad no habilitada en el padrón.")
        if not self.open:
            raise ValueError("La elección está cerrada.")
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64(request["client_public"]))
        private = ec.generate_private_key(ec.SECP256R1())
        public = b64(private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
        sid, nonce = secrets.token_hex(16), b64(secrets.token_bytes(16))
        transcript = {"election": ELECTION_ID, "session": sid, "voter": voter_id,
                      "client_public": request["client_public"], "server_public": public, "server_nonce": nonce}
        signature = self.signing_key.sign(json_bytes(transcript))
        self.pending[sid] = Pending(private, request["client_public"], nonce, voter_id)
        return {**transcript, "server_signature": b64(signature)}

    def accept_vote(self, envelope: dict[str, str]) -> dict[str, str]:
        voter_id = envelope.get("voter", "")
        public = self.voters.get(voter_id)
        if public is None:
            raise ValueError("Votante no habilitado.")
        unsigned = {k: v for k, v in envelope.items() if k != "signature"}
        try:
            public.verify(unb64(envelope["signature"]), json_bytes(unsigned))
        except (InvalidSignature, KeyError, ValueError) as exc:
            raise ValueError("Firma Ed25519 inválida: el sobre fue alterado o no es auténtico.") from exc
        if not self.open:
            raise ValueError("La elección está cerrada.")
        if voter_id in self.used:
            raise ValueError("Este votante ya emitió un sufragio.")
        sid = envelope["session"]
        pending = self.pending.get(sid)
        if not pending or pending.voter_id != voter_id or pending.client_public != envelope["client_public"]:
            raise ValueError("Sesión ECDH inválida o no asociada a esta identidad.")
        if envelope["election"] != ELECTION_ID:
            raise ValueError("El sobre corresponde a otra elección.")
        client_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), unb64(pending.client_public))
        shared = pending.private_key.exchange(ec.ECDH(), client_public)
        client_nonce = unb64(envelope["client_nonce"])
        key = derive_key(shared, unb64(pending.server_nonce), client_nonce, sid)
        aad = json_bytes({"election": ELECTION_ID, "session": sid, "voter": voter_id,
                          "server_nonce": pending.server_nonce, "client_nonce": envelope["client_nonce"]})
        try:
            clear = AESGCM(key).decrypt(unb64(envelope["nonce"]), unb64(envelope["ciphertext_tag"]), aad)
            choice = json.loads(clear.decode("utf-8"))["choice"]
        except (InvalidTag, KeyError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("AES-GCM rechazó el voto: etiqueta o contenido inválido.") from exc
        if choice not in self.candidates:
            raise ValueError("La opción descifrada no pertenece a esta elección.")
        stored = {"nonce": envelope["nonce"], "ciphertext_tag": envelope["ciphertext_tag"]}
        mac = hmac.new(self.audit_key, json_bytes(stored), hashlib.sha256).hexdigest()
        self.ballots.append({**stored, "hmac": mac})
        self.results[choice] += 1
        self.used.add(voter_id)
        del self.pending[sid]
        return {"receipt": hashlib.sha256(unb64(envelope["ciphertext_tag"])).hexdigest()}

    def audit(self) -> tuple[bool, str]:
        for i, ballot in enumerate(self.ballots, 1):
            body = {"nonce": ballot["nonce"], "ciphertext_tag": ballot["ciphertext_tag"]}
            expected = hmac.new(self.audit_key, json_bytes(body), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, ballot["hmac"]):
                return False, f"HMAC inválido en papeleta {i}."
        return True, f"{len(self.ballots)} papeleta(s): HMAC-SHA-256 válido."

    def close_and_sign(self) -> tuple[dict[str, Any], str]:
        ok, detail = self.audit()
        if not ok:
            raise ValueError(detail)
        self.open = False
        self.minutes = {"eleccion": ELECTION_ID, "organizacion": self.organization,
                        "fecha_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "total_votos": len(self.ballots), "resultados": self.results.copy()}
        signature = b64(self.signing_key.sign(json_bytes(self.minutes)))
        self.signing_key.public_key().verify(unb64(signature), json_bytes(self.minutes))
        self.minutes_signature = signature
        return self.minutes, signature

class LocalTLSServer:
    """Servidor HTTPS real, limitado a loopback (127.0.0.1)."""
    def __init__(self, election: ElectionServer, temp_path: Path) -> None:
        self.election = election
        cert_file, key_file = temp_path / "server.pem", temp_path / "server-key.pem"
        cert_file.write_bytes(election.certificate_pem)
        key_file.write_bytes(election.signing_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if size < 1 or size > 128_000:
                        raise ValueError("Tamaño de solicitud inválido.")
                    payload = json.loads(self.rfile.read(size).decode("utf-8"))
                    if self.path == "/handshake":
                        result = owner.election.handshake(payload)
                    elif self.path == "/vote":
                        result = owner.election.accept_vote(payload)
                    else:
                        self.send_error(404)
                        return
                    self._respond(200, result)
                except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                    self._respond(400, {"error": str(exc)})
            def _respond(self, status: int, obj: dict[str, str]) -> None:
                body = json_bytes(obj)
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, fmt: str, *args: Any) -> None:
                pass
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(cert_file), str(key_file))
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.httpd.server_address[1]}"
        self.cert_file = cert_file
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

class VotingClient:
    """Terminal: verifica identidad, negocia ECDH, cifra y firma el sobre."""
    def __init__(self, transport: LocalTLSServer, server: ElectionServer, pinned_fingerprint: str) -> None:
        self.transport, self.server = transport, server
        self.pin = pinned_fingerprint.lower()
        self.context = ssl.create_default_context(cafile=str(transport.cert_file))
        self.context.check_hostname = True
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
    def post(self, path: str, body: dict[str, str]) -> dict[str, str]:
        req = urllib.request.Request(self.transport.url + path, data=json_bytes(body),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, context=self.context, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                error = json.loads(exc.read().decode("utf-8")).get("error", f"HTTP {exc.code}")
            except json.JSONDecodeError:
                error = f"HTTP {exc.code}"
            raise ValueError(error) from exc
        except (urllib.error.URLError, ssl.SSLError, TimeoutError) as exc:
            raise ValueError(f"Canal HTTPS/TLS no confiable: {exc}") from exc
    def vote(self, wallet: VoterWallet, choice: str) -> tuple[dict[str, str], str]:
        if not hmac.compare_digest(self.server.fingerprint, self.pin):
            raise ValueError("Huella del servidor no coincide: conexión detenida por posible MITM.")
        client_private = ec.generate_private_key(ec.SECP256R1())
        client_public = b64(client_private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
        handshake = self.post("/handshake", {"voter_id": wallet.voter_id, "client_public": client_public})
        cert = x509.load_pem_x509_certificate(self.transport.cert_file.read_bytes())
        if not hmac.compare_digest(cert.fingerprint(hashes.SHA256()).hex(), self.pin):
            raise ValueError("Huella X.509 inválida: posible servidor falso.")
        cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
        transcript = {k: handshake[k] for k in (
            "election", "session", "voter", "client_public", "server_public", "server_nonce")}
        cert.public_key().verify(unb64(handshake["server_signature"]), json_bytes(transcript))
        server_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), unb64(handshake["server_public"]))
        shared = client_private.exchange(ec.ECDH(), server_public)
        client_nonce = b64(secrets.token_bytes(16))
        key = derive_key(shared, unb64(handshake["server_nonce"]), unb64(client_nonce), handshake["session"])
        aad = json_bytes({"election": ELECTION_ID, "session": handshake["session"], "voter": wallet.voter_id,
                          "server_nonce": handshake["server_nonce"], "client_nonce": client_nonce})
        nonce = secrets.token_bytes(12)
        ciphertext_tag = AESGCM(key).encrypt(nonce, json_bytes({"choice": choice}), aad)
        unsigned = {"election": ELECTION_ID, "session": handshake["session"], "voter": wallet.voter_id,
                    "client_public": client_public, "client_nonce": client_nonce,
                    "nonce": b64(nonce), "ciphertext_tag": b64(ciphertext_tag)}
        envelope = {**unsigned, "signature": b64(wallet.private_key.sign(json_bytes(unsigned)))}
        result = self.post("/vote", envelope)
        return envelope, result["receipt"]


# ═══════════════════════════ INTERFAZ (PySide6) ═══════════════════════════
from PySide6.QtCore import QByteArray, QSize, Qt, QTimer
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QRadioButton, QStackedWidget,
    QTableWidget, QTableWidgetItem, QToolButton, QVBoxLayout, QWidget)

NAVY, RED = "#0b2e59", "#c8102e"
ICONS = {
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1"/>',
    "users": '<circle cx="9" cy="8" r="3.5"/><path d="M2 21v-1a6 6 0 0 1 6-6h2a6 6 0 0 1 6 6v1M17 4.5a3.5 3.5 0 0 1 0 7M22 21v-1a6 6 0 0 0-4-5.6"/>',
    "lock": '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    "check": '<circle cx="12" cy="12" r="10"/><path d="m8 12 3 3 5-6"/>',
    "home": '<path d="M3 11l9-8 9 8M5 10v10h5v-6h4v6h5V10"/>',
    "sliders": '<path d="M4 6h8M18 6h2M4 12h2M12 12h8M4 18h10M20 18h0"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>',
    "pulse": '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    "file": '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6M8 13h8M8 17h5"/>',
    "exit": '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
    "server": '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    "alert": '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
    "edit": '<path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
    "down": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
    "flag": '<path d="M4 22V4M4 4h13l-2 4 2 4H4"/>',
    "arrow": '<path d="M5 12h14M13 6l6 6-6 6"/>',
    "back": '<path d="M19 12H5M11 6l-6 6 6 6"/>',
    "copy": '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/>',
    "hash": '<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>',
    "wand": '<path d="m15 4 5 5L8 21l-5-5zM13 6l5 5"/>',
}


def icon(name: str, color: str = "#ffffff") -> QIcon:
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="%s" '
           'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">%s</svg>' % (color, ICONS[name]))
    pm = QPixmap(96, 96)
    pm.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pm)
    QSvgRenderer(QByteArray(svg.encode())).render(painter)
    painter.end()
    return QIcon(pm)


QSS = f"""
* {{ font-family: 'Segoe UI', 'Inter', sans-serif; font-size: 14px; color: #18212d; }}
#side {{ background: {NAVY}; }}
#side QToolButton {{ border: 0; border-left: 3px solid transparent; padding: 14px; background: transparent; }}
#side QToolButton:hover {{ background: #14407a; }}
#side QToolButton:checked {{ background: #14407a; border-left: 3px solid {RED}; }}
#main, QStackedWidget {{ background: #f2f4f7; }}
QFrame#card {{ background: #fff; border: 1px solid #d3d9e1; border-radius: 6px; }}
QLabel {{ background: transparent; }}
QLabel#h {{ font-size: 22px; font-weight: 600; color: {NAVY}; }}
QLabel#mut {{ color: #5b6877; font-size: 12px; }}
QLabel#kpi {{ font-size: 26px; font-weight: 700; color: {NAVY}; }}
QLabel#mono {{ font-family: Consolas, monospace; font-size: 12px; }}
QLineEdit, QPlainTextEdit {{ border: 1px solid #c5ced9; border-radius: 4px; padding: 8px; background: #fff; }}
QLineEdit:focus, QPlainTextEdit:focus {{ border: 1px solid #1459a8; }}
QPlainTextEdit#log {{ background: #0f1c2e; color: #cfe0f5; font-family: Consolas, monospace; font-size: 12px; border: 0; }}
QPushButton {{ border-radius: 4px; padding: 10px 18px; font-weight: 600; }}
QPushButton[k="p"] {{ background: #1459a8; border: 0; color: #fff; }}
QPushButton[k="p"]:hover {{ background: {NAVY}; }}
QPushButton[k="d"] {{ background: {RED}; border: 0; color: #fff; }}
QPushButton[k="g"] {{ background: #fff; border: 1px solid #c5ced9; color: {NAVY}; }}
QPushButton[k="g"]:hover {{ background: #eef2f7; }}
QPushButton[k="t"] {{ background: #fff; border: 1px solid #d3d9e1; border-radius: 6px; padding: 28px 20px; font-size: 16px; color: {NAVY}; }}
QPushButton[k="t"]:hover {{ border: 1px solid #1459a8; background: #f5f9ff; }}
QPushButton:disabled {{ background: #e3e8ef; color: #9aa6b4; border: 0; }}
QRadioButton {{ padding: 10px 12px; border: 1px solid #d3d9e1; border-radius: 4px; background: #fff; }}
QRadioButton:checked {{ border: 1px solid #1459a8; background: #eef5ff; }}
QProgressBar {{ border: 0; background: #e3e8ef; max-height: 8px; border-radius: 4px; }}
QProgressBar::chunk {{ background: #1459a8; border-radius: 4px; }}
QTableWidget {{ border: 1px solid #d3d9e1; gridline-color: #e3e8ef; background: #fff; }}
QHeaderView::section {{ background: #eef2f7; border: 0; padding: 6px; font-weight: 600; }}
"""


def clear(layout) -> None:
    while layout.count():
        w = layout.takeAt(0).widget()
        if w:
            w.deleteLater()


def button(text: str, ic: str, kind: str = "p", tip: str = "") -> QPushButton:
    b = QPushButton(text)
    b.setProperty("k", kind)
    b.setIcon(icon(ic, "#ffffff" if kind in "pd" else NAVY))
    b.setIconSize(QSize(18 if kind != "t" else 40, 18 if kind != "t" else 40))
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    b.setToolTip(tip or text)
    return b


def field(ic: str, placeholder: str, secret: bool = False) -> QLineEdit:
    e = QLineEdit()
    e.setPlaceholderText(placeholder)
    e.addAction(icon(ic, "#7b8896"), QLineEdit.ActionPosition.LeadingPosition)
    if secret:
        e.setEchoMode(QLineEdit.EchoMode.Password)
    return e


class App(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Voto Seguro")
        self.resize(1020, 700)
        self.setMinimumSize(880, 620)
        self.srv: ElectionServer | None = None
        self.transport: LocalTLSServer | None = None
        self.client: VotingClient | None = None
        self.tmp: tempfile.TemporaryDirectory[str] | None = None
        self.wallets: dict[str, VoterWallet] = {}
        self.hcodes: dict[str, str] = {}
        self.tries: dict[str, int] = {}
        self.codes: list[tuple[str, str, str]] = []
        self.verifier: dict[str, str | int] | None = None
        self.admin_ok, self.role, self.last_env = False, None, None
        self.fails, self.locked = 0, 0.0

        root = QWidget(objectName="main")
        lay = QHBoxLayout(root)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        self.setCentralWidget(root)
        self.side = QFrame(objectName="side")
        self.side.setFixedWidth(64)
        sl = QVBoxLayout(self.side)
        sl.setContentsMargins(0, 10, 0, 10)
        sl.setSpacing(0)
        logo = QLabel()
        logo.setPixmap(icon("shield", "#ffffff").pixmap(30, 30))
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sl.addWidget(logo)
        sl.addSpacing(14)
        self.nav: dict[int, QToolButton] = {}
        for idx, ic, tip in [(0, "home", "Inicio"), (3, "sliders", "Configurar"), (4, "pulse", "Auditoría"), (5, "file", "Acta")]:
            t = QToolButton()
            t.setIcon(icon(ic))
            t.setIconSize(QSize(24, 24))
            t.setToolTip(tip)
            t.setCheckable(True)
            t.setCursor(Qt.CursorShape.PointingHandCursor)
            t.clicked.connect(lambda _=False, i=idx: self.go(i))
            sl.addWidget(t)
            self.nav[idx] = t
        sl.addStretch()
        self.exit_btn = QToolButton()
        self.exit_btn.setIcon(icon("exit"))
        self.exit_btn.setIconSize(QSize(24, 24))
        self.exit_btn.setToolTip("Salir")
        self.exit_btn.clicked.connect(self.logout)
        sl.addWidget(self.exit_btn)
        lay.addWidget(self.side)
        self.stack = QStackedWidget()
        lay.addWidget(self.stack, 1)
        for build in (self.p_home, self.p_login, self.p_voter, self.p_config, self.p_audit, self.p_acta):
            self.stack.addWidget(build())
        self.toastl = QLabel(self)
        self.toastl.hide()
        self.tt = QTimer(self, singleShot=True, timeout=self.toastl.hide)
        self.go(0)

    # ---------- utilidades ----------
    def toast(self, msg: str, bad: bool = False) -> None:
        t = self.toastl
        t.setText(msg)
        t.setStyleSheet(f"background:{RED if bad else NAVY};color:#fff;padding:10px 16px;border-radius:4px")
        t.adjustSize()
        t.move(self.width() - t.width() - 24, self.height() - t.height() - 24)
        t.show()
        t.raise_()
        self.tt.start(4500)

    def log(self, msg: str) -> None:
        self.logbox.appendPlainText(f"[{datetime.now():%H:%M:%S}] {msg}")

    def page(self, title: str, ic: str) -> tuple[QWidget, QVBoxLayout]:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(36, 30, 36, 24)
        v.setSpacing(16)
        head = QHBoxLayout()
        pic = QLabel()
        pic.setPixmap(icon(ic, NAVY).pixmap(28, 28))
        head.addWidget(pic)
        head.addWidget(QLabel(title, objectName="h"))
        head.addStretch()
        v.addLayout(head)
        return w, v

    def card(self) -> tuple[QFrame, QVBoxLayout]:
        f = QFrame(objectName="card")
        v = QVBoxLayout(f)
        v.setContentsMargins(20, 18, 20, 18)
        v.setSpacing(12)
        return f, v

    def go(self, i: int) -> None:
        self.stack.setCurrentIndex(i)
        for k, b in self.nav.items():
            b.setChecked(k == i)
            b.setVisible(k == 0 or self.admin_ok)
        self.exit_btn.setVisible(self.role is not None)
        self.refresh()

    # ---------- páginas ----------
    def p_home(self) -> QWidget:
        w, v = self.page("Voto Seguro", "shield")
        row = QHBoxLayout()
        row.setSpacing(16)
        self.tile_vote = button("Votar", "check", "t")
        self.tile_vote.clicked.connect(self.enter_voter)
        tile_admin = button("Comité", "users", "t")
        tile_admin.clicked.connect(self.enter_admin)
        row.addWidget(self.tile_vote)
        row.addWidget(tile_admin)
        v.addLayout(row)
        self.home_info = QLabel("Sin elección", objectName="mut")
        v.addWidget(self.home_info)
        v.addStretch()
        v.addWidget(QLabel("Prototipo académico · datos ficticios", objectName="mut"))
        return w

    def p_login(self) -> QWidget:
        w, v = self.page("Comité", "lock")
        c, cv = self.card()
        c.setMaximumWidth(420)
        self.pw = field("lock", "Contraseña", True)
        self.pw2 = field("lock", "Confirmar contraseña", True)
        self.pw.returnPressed.connect(self.login)
        self.pw2.returnPressed.connect(self.login)
        cv.addWidget(self.pw)
        cv.addWidget(self.pw2)
        row = QHBoxLayout()
        enter = button("Entrar", "arrow")
        enter.clicked.connect(self.login)
        back = button("", "back", "g", "Atrás")
        back.clicked.connect(lambda: self.go(0))
        row.addWidget(enter, 1)
        row.addWidget(back)
        cv.addLayout(row)
        v.addWidget(c)
        v.addStretch()
        return w

    def p_voter(self) -> QWidget:
        w, v = self.page("Cabina", "check")
        self.vstack = QStackedWidget()
        form, fv = self.card()
        form.setMaximumWidth(520)
        self.vid = field("user", "Identificador")
        self.vcode = field("lock", "Código", True)
        fv.addWidget(self.vid)
        fv.addWidget(self.vcode)
        self.cand_lay = QVBoxLayout()
        self.cand_lay.setSpacing(8)
        fv.addLayout(self.cand_lay)
        send = button("Votar", "shield", "p", "Cifrar, firmar y enviar")
        send.clicked.connect(self.vote)
        fv.addWidget(send)
        done, dv = self.card()
        done.setMaximumWidth(520)
        ok = QLabel()
        ok.setPixmap(icon("check", "#1b7a43").pixmap(56, 56))
        dv.addWidget(ok)
        dv.addWidget(QLabel("Voto registrado", objectName="h"))
        self.receipt = QLabel(objectName="mono")
        self.receipt.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        dv.addWidget(self.receipt)
        row = QHBoxLayout()
        cp = button("Copiar", "copy", "g")
        cp.clicked.connect(lambda: (QApplication.clipboard().setText(self.receipt.text().replace("\n", "")), self.toast("Copiado")))
        fin = button("Listo", "check")
        fin.clicked.connect(self.logout)
        row.addWidget(cp)
        row.addWidget(fin)
        dv.addLayout(row)
        self.vstack.addWidget(form)
        self.vstack.addWidget(done)
        v.addWidget(self.vstack, 0, Qt.AlignmentFlag.AlignTop)
        v.addStretch()
        return w

    def p_config(self) -> QWidget:
        w, v = self.page("Configurar", "sliders")
        self.org = field("users", "Organización")
        v.addWidget(self.org)
        row = QHBoxLayout()
        self.roster = QPlainTextEdit()
        self.roster.setPlaceholderText("ID, Nombre")
        self.cands = QPlainTextEdit()
        self.cands.setPlaceholderText("Candidaturas")
        row.addWidget(self.roster, 3)
        row.addWidget(self.cands, 2)
        v.addLayout(row, 2)
        bar = QHBoxLayout()
        ex = button("Ejemplo", "wand", "g")
        ex.clicked.connect(self.example)
        mk = button("Crear", "server")
        mk.clicked.connect(self.create)
        csv = button("CSV", "down", "g", "Exportar códigos")
        csv.clicked.connect(self.export_codes)
        for b in (ex, mk):
            bar.addWidget(b)
        bar.addStretch()
        bar.addWidget(csv)
        v.addLayout(bar)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["ID", "Nombre", "Código"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().hide()
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        v.addWidget(self.table, 2)
        return w

    def p_audit(self) -> QWidget:
        w, v = self.page("Auditoría", "pulse")
        row = QHBoxLayout()
        row.setSpacing(12)
        self.k = {}
        for key, ic in (("voters", "users"), ("votes", "hash"), ("state", "flag")):
            c, cv = self.card()
            r = QHBoxLayout()
            pic = QLabel()
            pic.setPixmap(icon(ic, "#1459a8").pixmap(26, 26))
            self.k[key] = QLabel("0", objectName="kpi")
            r.addWidget(pic)
            r.addWidget(self.k[key])
            r.addStretch()
            cv.addLayout(r)
            row.addWidget(c)
        v.addLayout(row)
        bar = QHBoxLayout()
        for text, ic, fn in (("Certificado", "shield", self.act_cert), ("HMAC", "hash", self.act_audit),
                             ("MITM", "alert", self.act_mitm), ("Alteración", "edit", self.act_tamper)):
            b = button(text, ic, "g")
            b.clicked.connect(fn)
            bar.addWidget(b)
        bar.addStretch()
        v.addLayout(bar)
        self.logbox = QPlainTextEdit(objectName="log")
        self.logbox.setReadOnly(True)
        v.addWidget(self.logbox, 1)
        return w

    def p_acta(self) -> QWidget:
        w, v = self.page("Acta", "file")
        bar = QHBoxLayout()
        self.close_btn = button("Cerrar y firmar", "flag", "d")
        self.close_btn.clicked.connect(self.close_election)
        self.exp_btn = button("Exportar", "down", "g", "Exportar acta firmada")
        self.exp_btn.clicked.connect(self.export_acta)
        bar.addWidget(self.close_btn)
        bar.addWidget(self.exp_btn)
        bar.addStretch()
        v.addLayout(bar)
        c, cv = self.card()
        self.res_lay = QVBoxLayout()
        self.res_lay.setSpacing(10)
        cv.addLayout(self.res_lay)
        self.sig = QLabel(objectName="mono")
        self.sig.setWordWrap(True)
        cv.addWidget(self.sig)
        v.addWidget(c)
        v.addStretch()
        return w

    # ---------- acciones ----------
    def refresh(self) -> None:
        e = self.srv
        self.k["voters"].setText(str(len(self.wallets)))
        self.k["votes"].setText(str(len(e.ballots) if e else 0))
        self.k["state"].setText("—" if not e else "Abierta" if e.open else "Cerrada")
        self.tile_vote.setEnabled(bool(e and e.open))
        self.home_info.setText("Sin elección" if not e else f"{e.organization} · {'abierta' if e.open else 'cerrada'} · {len(e.ballots)}/{len(self.wallets)} votos")
        self.close_btn.setEnabled(bool(e and e.open))
        self.exp_btn.setEnabled(bool(e and e.minutes))
        clear(self.res_lay)
        self.sig.setText("")
        if e and e.minutes:
            total = max(e.minutes["total_votos"], 1)
            for name, n in e.minutes["resultados"].items():
                self.res_lay.addWidget(QLabel(f"{name}  ·  {n}"))
                bar = QProgressBar()
                bar.setRange(0, total)
                bar.setValue(n)
                bar.setTextVisible(False)
                self.res_lay.addWidget(bar)
            self.sig.setText("Firma Ed25519: " + (e.minutes_signature or ""))

    def enter_admin(self) -> None:
        if self.admin_ok:
            return self.go(3)
        self.pw.clear()
        self.pw2.clear()
        self.pw2.setVisible(self.verifier is None)
        self.pw.setPlaceholderText("Contraseña (mín. 10)" if self.verifier is None else "Contraseña")
        self.go(1)
        self.pw.setFocus()

    def login(self) -> None:
        try:
            if time.time() < self.locked:
                raise ValueError(f"Espera {int(self.locked - time.time()) + 1} s.")
            pw = self.pw.text()
            if self.verifier is None:
                if pw != self.pw2.text():
                    raise ValueError("Las contraseñas no coinciden.")
                self.verifier = make_admin_verifier(pw)
            elif not verify_admin_password(pw, self.verifier):
                self.fails += 1
                if self.fails >= 5:
                    self.fails, self.locked = 0, time.time() + 30
                raise ValueError("Contraseña incorrecta.")
        except ValueError as exc:
            return self.toast(str(exc), True)
        self.fails, self.admin_ok, self.role = 0, True, "admin"
        self.go(3)

    def logout(self) -> None:
        self.admin_ok, self.role = False, None
        self.go(0)

    def example(self) -> None:
        self.org.setText("Junta Vecinal Demo")
        self.roster.setPlainText("VEC-001, Ana de prueba\nVEC-002, Bruno de prueba\nVEC-003, Carla de prueba")
        self.cands.setPlainText("Lista Vecinal A\nLista Vecinal B\nVoto en blanco")

    def create(self) -> None:
        try:
            org = self.org.text().strip()
            cands = [x.strip() for x in self.cands.toPlainText().splitlines() if x.strip()]
            if not org:
                raise ValueError("Falta la organización.")
            if len(cands) < 2 or len(set(cands)) != len(cands):
                raise ValueError("Mínimo 2 candidaturas distintas.")
            if self.srv and self.srv.open and self.srv.ballots:
                raise ValueError("Cierra la elección actual primero.")
            wallets, codes, rows = {}, {}, []
            for line in self.roster.toPlainText().splitlines():
                if not line.strip():
                    continue
                p = [x.strip() for x in line.split(",", 1)]
                if len(p) != 2 or not all(p):
                    raise ValueError(f"Formato: ID, Nombre → {line}")
                if p[0] in wallets:
                    raise ValueError(f"ID repetido: {p[0]}")
                wallets[p[0]] = VoterWallet(p[0], ed25519.Ed25519PrivateKey.generate())
                codes[p[0]] = secrets.token_urlsafe(6)
                rows.append((p[0], p[1], codes[p[0]]))
            if not wallets:
                raise ValueError("Falta el padrón.")
        except ValueError as exc:
            return self.toast(str(exc), True)
        self.stop()
        self.tmp = tempfile.TemporaryDirectory(prefix=".voto_tls_", dir=Path(__file__).resolve().parent)
        self.srv = ElectionServer(org, cands, {k: v.private_key.public_key() for k, v in wallets.items()})
        self.transport = LocalTLSServer(self.srv, Path(self.tmp.name))
        self.client = VotingClient(self.transport, self.srv, self.srv.fingerprint)
        self.wallets, self.tries, self.last_env, self.codes = wallets, {}, None, rows
        self.hcodes = {r[0]: hashlib.sha256(r[2].encode()).hexdigest() for r in rows}
        encrypt_roster([{"id": r[0], "nombre": r[1]} for r in rows])
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            for j, val in enumerate(r):
                self.table.setItem(i, j, QTableWidgetItem(val))
        self.logbox.clear()
        self.log(f"Elección creada: {org}. Padrón AES-256-GCM, claves Ed25519, TLS activo.")
        self.toast("Elección creada")
        self.refresh()

    def enter_voter(self) -> None:
        if not (self.srv and self.srv.open):
            return
        self.role = "voter"
        self.vid.clear()
        self.vcode.clear()
        clear(self.cand_lay)
        for c in self.srv.candidates:
            self.cand_lay.addWidget(QRadioButton(c))
        self.vstack.setCurrentIndex(0)
        self.go(2)
        self.vid.setFocus()

    def vote(self) -> None:
        e = self.srv
        vid, code = self.vid.text().strip(), self.vcode.text().strip()
        pick = next((r.text() for r in self.findChildren(QRadioButton) if r.isChecked()), "")
        if not (e and e.open and vid and code and pick):
            return self.toast("Completa los campos", True)
        if self.tries.get(vid, 0) >= 5:
            return self.toast("Identificador bloqueado", True)
        h = self.hcodes.get(vid)
        if not h or not hmac.compare_digest(h, hashlib.sha256(code.encode()).hexdigest()):
            self.tries[vid] = self.tries.get(vid, 0) + 1
            self.vcode.clear()
            self.log("Identidad rechazada en cabina.")
            return self.toast("ID o código incorrecto", True)
        if QMessageBox.question(self, "Confirmar", "¿Enviar voto cifrado? No se puede cambiar.") != QMessageBox.StandardButton.Yes:
            return
        try:
            self.last_env, receipt = self.client.vote(self.wallets[vid], pick)
        except (ValueError, InvalidSignature) as exc:
            return self.toast(str(exc), True)
        self.tries.pop(vid, None)
        self.log("Voto aceptado: ECDH + Ed25519 + AES-256-GCM sobre TLS.")
        self.receipt.setText(receipt[:32] + "\n" + receipt[32:])
        self.vstack.setCurrentIndex(1)

    def need(self) -> bool:
        if not self.srv:
            self.toast("Crea la elección primero", True)
        return self.srv is not None

    def act_cert(self) -> None:
        if self.need():
            c = self.srv.certificate
            c.public_key().verify(c.signature, c.tbs_certificate_bytes)
            self.log("Certificado X.509 y huella fijada coinciden (autosellado).")
            self.toast("Certificado válido")

    def act_audit(self) -> None:
        if self.need():
            ok, d = self.srv.audit()
            self.log(("OK: " if ok else "ALERTA: ") + d)
            self.toast(d, not ok)

    def act_mitm(self) -> None:
        if self.need():
            try:
                VotingClient(self.transport, self.srv, "00" * 32).vote(next(iter(self.wallets.values())), self.srv.candidates[0])
            except ValueError as exc:
                self.log("MITM detectado: " + str(exc))
                self.toast("MITM detectado")

    def act_tamper(self) -> None:
        if not self.need():
            return
        if not self.last_env:
            return self.toast("Emite un voto primero", True)
        try:
            self.client.post("/vote", dict(self.last_env, ciphertext_tag=b64(b"alterado")))
        except ValueError as exc:
            self.log("Alteración detectada: " + str(exc))
            self.toast("Alteración detectada")

    def close_election(self) -> None:
        if not self.need() or QMessageBox.question(self, "Cerrar", "¿Cerrar y firmar el acta?") != QMessageBox.StandardButton.Yes:
            return
        try:
            m, sig = self.srv.close_and_sign()
            self.srv.certificate.public_key().verify(unb64(sig), json_bytes(m))
        except (ValueError, InvalidSignature) as exc:
            return self.toast(str(exc), True)
        self.log("Acta cerrada y firma verificada.")
        self.toast("Acta firmada")
        self.refresh()

    def save(self, name: str, text: str) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Guardar", name)
        if path:
            Path(path).write_text(text, encoding="utf-8")
            self.toast("Guardado")

    def export_codes(self) -> None:
        if self.codes:
            q = lambda x: '"' + x.replace('"', '""') + '"'
            self.save("codigos.csv", "ID,Nombre,Codigo\n" + "\n".join(",".join(q(c) for c in r) for r in self.codes))

    def export_acta(self) -> None:
        if self.srv and self.srv.minutes:
            self.save("acta.json", json.dumps({"acta": self.srv.minutes, "firma_ed25519": self.srv.minutes_signature}, ensure_ascii=False, indent=2))

    def stop(self) -> None:
        if self.transport:
            self.transport.close()
        if self.tmp:
            self.tmp.cleanup()
        self.transport = self.tmp = None

    def closeEvent(self, event) -> None:
        self.stop()
        super().closeEvent(event)


def main() -> None:
    app = QApplication(sys.argv)
    app.setStyleSheet(QSS)
    window = App()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
