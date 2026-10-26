"""Interfaz gráfica del prototipo de votación comunitaria - Avance 2.

Requisitos: Python 3.10+ y cryptography (py -m pip install cryptography).
Ejecución: py prototipo_avance2.py

Usa HTTPS real en localhost y una simulación de identidad/voto en memoria.
Solo para una práctica académica con datos ficticios.
"""
from __future__ import annotations

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
import tkinter as tk
from tkinter import messagebox, ttk

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
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return {"salt": b64(salt), "verifier": b64(digest), "iterations": 100_000}

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

class VotingGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("Voto Seguro Comunitario | Avance 2")
        root.geometry("1120x790")
        root.minsize(960, 680)
        self.server: ElectionServer | None = None
        self.transport: LocalTLSServer | None = None
        self.client: VotingClient | None = None
        self.tempdir: tempfile.TemporaryDirectory[str] | None = None
        self.wallets: dict[str, VoterWallet] = {}
        self.voter_access_codes: dict[str, str] = {}
        self.admin_verifier: dict[str, str | int] | None = None
        self.admin_authenticated = False
        self.active_role: str | None = None
        self.last_envelope: dict[str, str] | None = None
        self.org = tk.StringVar()
        self.voter = tk.StringVar()
        self.choice = tk.StringVar()
        self.status = tk.StringVar(value="Ingresa datos y crea una elección de práctica.")
        self._style()
        self._build()
        root.protocol("WM_DELETE_WINDOW", self.close)
    def _style(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#f3f6fb")
        style.configure("TLabel", background="#f3f6fb", foreground="#1d2a3a", font=("Segoe UI", 10))
        style.configure("Title.TLabel", background="#f3f6fb", foreground="#142b4a", font=("Segoe UI", 20, "bold"))
        style.configure("TButton", font=("Segoe UI", 10), padding=(10, 6))
        style.configure("Accent.TButton", background="#1565c0", foreground="white", font=("Segoe UI", 10, "bold"))
        style.configure("TNotebook", background="#f3f6fb", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(14, 8), font=("Segoe UI", 10, "bold"))
        style.configure("Treeview", rowheight=26, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
    def _build(self) -> None:
        header = ttk.Frame(self.root, padding=(22, 15, 22, 4)); header.pack(fill="x")
        ttk.Label(header, text="Voto Seguro Comunitario", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Avance 2 · ECDH + HTTPS/TLS + AES-256-GCM + Ed25519").pack(anchor="w")
        self.portal = ttk.Frame(self.root, padding=30)
        self.login_page = ttk.Frame(self.root, padding=30)
        self.rolebar = ttk.Frame(self.root, padding=(20, 5, 20, 0))
        self.portal.pack(fill="both", expand=True, padx=20, pady=10)
        self._build_portal()
        self._build_admin_login()
        self.tabs = ttk.Notebook(self.root)
        self.setup = ttk.Frame(self.tabs, padding=15); self.ballot = ttk.Frame(self.tabs, padding=15)
        self.audit = ttk.Frame(self.tabs, padding=15); self.sequence = ttk.Frame(self.tabs, padding=15)
        self.threats = ttk.Frame(self.tabs, padding=15)
        for frame, title in [(self.setup,"1 · Configurar"),(self.ballot,"2 · Cabina"),(self.audit,"3 · Auditoría y acta"),
                             (self.sequence,"Protocolo"),(self.threats,"Amenazas")]:
            self.tabs.add(frame, text=title)
        self._setup_tab(); self._ballot_tab(); self._audit_tab(); self._sequence_tab(); self._threat_tab()
        self._set_role_tabs([])
        self.role_label=ttk.Label(self.rolebar, text="Vista del comité electoral")
        self.role_label.pack(side="left")
        ttk.Button(self.rolebar, text="Salir y volver al inicio", command=self.logout).pack(side="right")
        self.tabs.pack_forget()
        footer = ttk.Frame(self.root, padding=(20, 3, 20, 10)); footer.pack(fill="x")
        ttk.Label(footer, textvariable=self.status, foreground="#315a82").pack(side="left")
        ttk.Label(footer, text="Usa solo datos ficticios · Prototipo, no sistema electoral real", foreground="#9b3d34").pack(side="right")
    def _build_portal(self) -> None:
        ttk.Label(self.portal, text="Elige tu acceso", style="Title.TLabel").pack(anchor="center", pady=(35, 10))
        ttk.Label(self.portal, text="El administrador configura y audita la elección. El votante solo accede a la cabina.", wraplength=720, justify="center").pack(pady=(0, 28))
        self.admin_access_button = ttk.Button(self.portal, text="Administración del comité", style="Accent.TButton", command=self.show_admin_login)
        self.admin_access_button.pack(pady=8, ipadx=30)
        self.voter_access_button = ttk.Button(self.portal, text="Cabina exclusiva del votante", command=self.show_voter_page, state="disabled")
        self.voter_access_button.pack(pady=8, ipadx=30)
        ttk.Label(self.portal, text="La cabina se habilita cuando el comité crea la elección.", foreground="#52657d").pack(pady=(10, 0))
    def _build_admin_login(self) -> None:
        ttk.Label(self.login_page, text="Acceso del comité electoral", style="Title.TLabel").pack(anchor="w", pady=(20, 10))
        self.login_message = ttk.Label(self.login_page, text="Primera vez: crea la contraseña administrativa para esta sesión.")
        self.login_message.pack(anchor="w", pady=(0, 16))
        form = ttk.Frame(self.login_page); form.pack(anchor="w")
        ttk.Label(form, text="Contraseña del comité").grid(row=0, column=0, sticky="w")
        self.login_password = ttk.Entry(form, show="•", width=34)
        self.login_password.grid(row=1, column=0, sticky="w", pady=(4, 12), padx=(0, 18))
        self.confirm_label = ttk.Label(form, text="Confirmar contraseña")
        self.confirm_label.grid(row=0, column=1, sticky="w")
        self.login_confirm = ttk.Entry(form, show="•", width=34)
        self.login_confirm.grid(row=1, column=1, sticky="w", pady=(4, 12))
        actions = ttk.Frame(self.login_page); actions.pack(anchor="w", pady=5)
        ttk.Button(actions, text="Ingresar al panel", style="Accent.TButton", command=self.admin_login).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Volver", command=self.logout).pack(side="left")
    def _set_role_tabs(self, names: list[str]) -> None:
        for tab_id in self.tabs.tabs():
            self.tabs.forget(tab_id)
        pages = {
            "setup": (self.setup, "Configuración"),
            "ballot": (self.ballot, "Cabina del votante"),
            "audit": (self.audit, "Auditoría y acta"),
            "sequence": (self.sequence, "Protocolo"),
            "threats": (self.threats, "Amenazas"),
        }
        for name in names:
            frame, label = pages[name]
            self.tabs.add(frame, text=label)
    def show_admin_login(self) -> None:
        self.portal.pack_forget()
        self.login_page.pack(fill="both", expand=True, padx=20, pady=10)
        self.login_password.delete(0, "end")
        self.login_confirm.delete(0, "end")
        if self.admin_verifier is None:
            self.login_message.config(text="Primera vez: crea una contraseña del comité de 10 o más caracteres.")
            self.confirm_label.grid()
            self.login_confirm.grid()
        else:
            self.login_message.config(text="Ingresa la contraseña del comité para abrir el panel administrativo.")
            self.confirm_label.grid_remove()
            self.login_confirm.grid_remove()
        self.login_password.focus_set()
    def admin_login(self) -> None:
        password=self.login_password.get()
        try:
            if self.admin_verifier is None:
                if password != self.login_confirm.get():
                    raise ValueError("Las contraseñas no coinciden.")
                self.admin_verifier=make_admin_verifier(password)
            elif not verify_admin_password(password,self.admin_verifier):
                raise ValueError("Contraseña administrativa incorrecta.")
        except ValueError as exc:
            messagebox.showerror("No se pudo ingresar",str(exc))
            return
        self.admin_authenticated=True
        self.active_role="admin"
        self.login_page.pack_forget()
        self.role_label.config(text="Sesión autenticada · Comité electoral")
        self._set_role_tabs(["setup","audit","sequence","threats"])
        self.rolebar.pack(fill="x")
        self.tabs.pack(fill="both",expand=True,padx=20,pady=10)
        self.tabs.select(self.setup)
        self.status.set("Panel administrativo abierto; la cabina del votante está en otro acceso.")
        self.login_password.delete(0,"end")
        self.login_confirm.delete(0,"end")
    def show_voter_page(self) -> None:
        if not self.server or not self.server.open:
            messagebox.showwarning("Cabina no disponible","El comité debe configurar una elección abierta primero.")
            return
        self.portal.pack_forget()
        self.active_role="voter"
        self.voter.set("")
        self.voter_pin.delete(0,"end")
        self.choice.set("")
        self.my_receipt.set("Tu comprobante aparecerá aquí después de votar.")
        self.role_label.config(text="Cabina exclusiva · Votante")
        self._set_role_tabs(["ballot"])
        self.rolebar.pack(fill="x")
        self.tabs.pack(fill="both",expand=True,padx=20,pady=10)
        self.tabs.select(self.ballot)
        self.status.set("Cabina del votante · ingresa tu identificador y tu código privado.")
        self.voter_box.focus_set()
    def logout(self) -> None:
        self.active_role=None
        self.admin_authenticated=False
        self.tabs.pack_forget()
        self.rolebar.pack_forget()
        self.login_page.pack_forget()
        self.portal.pack(fill="both",expand=True,padx=20,pady=10)
        self.login_password.delete(0,"end")
        self.login_confirm.delete(0,"end")
        self.voter.set("")
        self.voter_pin.delete(0,"end")
        self.status.set("Elige un acceso. Las funciones administrativas requieren la contraseña del comité.")
    def _setup_tab(self) -> None:
        f = self.setup
        ttk.Label(f, text="Configura la elección", style="Title.TLabel").grid(row=0,column=0,columnspan=2,sticky="w",pady=(0,12))
        ttk.Label(f,text="Organización social").grid(row=1,column=0,sticky="w")
        ttk.Entry(f,textvariable=self.org).grid(row=2,column=0,columnspan=2,sticky="ew",pady=4)
        ttk.Label(f,text="Padrón: una línea por votante, formato ID, Nombre").grid(row=3,column=0,sticky="w",pady=(12,3))
        ttk.Label(f,text="Candidaturas: una opción por línea").grid(row=3,column=1,sticky="w",pady=(12,3))
        self.roster=tk.Text(f,height=13,font=("Consolas",10),wrap="none")
        self.roster.grid(row=4,column=0,sticky="nsew",padx=(0,16),pady=(0,10))
        self.candidates=tk.Text(f,height=13,font=("Consolas",10))
        self.candidates.grid(row=4,column=1,sticky="nsew",pady=(0,10))
        ttk.Label(f,text="El padrón se cifra con AES-GCM. Ingresa identificadores inventados, nunca DNI reales.",wraplength=950).grid(row=5,column=0,columnspan=2,sticky="w",pady=5)
        controls=ttk.Frame(f); controls.grid(row=6,column=0,columnspan=2,sticky="w",pady=8)
        ttk.Button(controls,text="Cargar ejemplo",command=self.example).pack(side="left",padx=(0,8))
        ttk.Button(controls,text="Crear elección y servidor HTTPS",style="Accent.TButton",command=self.create).pack(side="left")
        ttk.Label(f,text="Códigos de acceso para entregar a los votantes",font=("Segoe UI",10,"bold")).grid(row=7,column=0,columnspan=2,sticky="w",pady=(7,2))
        self.codes_text=tk.Text(f,height=4,state="disabled",font=("Consolas",9),wrap="none")
        self.codes_text.grid(row=8,column=0,columnspan=2,sticky="ew")
        f.columnconfigure(0,weight=1); f.columnconfigure(1,weight=1); f.rowconfigure(4,weight=1)
    def _ballot_tab(self) -> None:
        f=self.ballot
        ttk.Label(f,text="Cabina de votación",style="Title.TLabel").pack(anchor="w")
        ttk.Label(f,text="Esta vista solo permite emitir un sufragio. No muestra el panel ni el padrón administrativo.",wraplength=950).pack(anchor="w",pady=(4,15))
        form=ttk.Frame(f,padding=15); form.pack(fill="x",pady=(0,12))
        ttk.Label(form,text="Identificador registrado").grid(row=0,column=0,sticky="w")
        ttk.Label(form,text="Código privado del votante").grid(row=0,column=1,sticky="w")
        ttk.Label(form,text="Candidatura").grid(row=0,column=2,sticky="w")
        self.voter_box=ttk.Entry(form,textvariable=self.voter,width=26); self.voter_box.grid(row=1,column=0,padx=(0,14),pady=5)
        self.voter_pin=ttk.Entry(form,show="•",width=24); self.voter_pin.grid(row=1,column=1,padx=(0,14),pady=5)
        self.choice_box=ttk.Combobox(form,textvariable=self.choice,state="readonly",width=25); self.choice_box.grid(row=1,column=2,padx=(0,14),pady=5)
        ttk.Button(form,text="Cifrar, firmar y enviar",style="Accent.TButton",command=self.cast).grid(row=1,column=3)
        self.my_receipt=tk.StringVar(value="Tu comprobante aparecerá aquí después de votar.")
        ttk.Label(f,textvariable=self.my_receipt,wraplength=950,font=("Consolas",10)).pack(anchor="w",pady=(22,8))
        ttk.Label(f,text="La selección no aparece en el comprobante. El ID y el código se validan por separado de la papeleta cifrada.",wraplength=950).pack(anchor="w")
    def _audit_tab(self) -> None:
        f=self.audit
        ttk.Label(f,text="Auditoría y acta",style="Title.TLabel").pack(anchor="w")
        self.pin_label=ttk.Label(f,text="Huella del certificado: sin elección configurada",wraplength=1000,font=("Consolas",9))
        self.pin_label.pack(anchor="w",pady=(8,10))
        actions=ttk.Frame(f); actions.pack(fill="x",pady=(0,10))
        for label,cmd in [("Verificar certificado/TLS",self.verify_cert),("Auditar HMAC",self.audit_votes),
                          ("Simular MITM",self.simulate_mitm),("Simular alteración",self.simulate_tamper),
                          ("Cerrar y firmar acta",self.close_election)]:
            ttk.Button(actions,text=label,command=cmd).pack(side="left",padx=(0,6))
        ttk.Label(f,text="Registro de eventos",font=("Segoe UI",12,"bold")).pack(anchor="w")
        self.log=tk.Text(f,height=12,state="disabled",wrap="word",font=("Consolas",9))
        self.log.pack(fill="both",expand=True,pady=(5,8))
        self.minutes=tk.Text(f,height=8,state="disabled",wrap="word",font=("Consolas",9))
        self.minutes.pack(fill="x")
    def _sequence_tab(self) -> None:
        f=self.sequence
        ttk.Label(f,text="Secuencia del protocolo híbrido",style="Title.TLabel").pack(anchor="w")
        tree=ttk.Treeview(f,columns=("terminal","server","committee"),show="headings",height=11)
        for col,title,width in [("terminal","Terminal del votante",330),("server","Servidor electoral",360),("committee","Comité electoral",300)]:
            tree.heading(col,text=title); tree.column(col,width=width)
        for row in [
            ("1. Crea clave ECDH P-256 efímera y nonce.","Recibe clave pública de la sesión.","—"),
            ("2. Recibe certificado X.509 y firma del handshake.","Firma intercambio con Ed25519.","—"),
            ("3. Verifica huella fijada y firma del servidor.","Entrega clave pública ECDH firmada.","—"),
            ("4. Deriva clave de sesión con HKDF-SHA-256.","Deriva la misma clave; no la transmite.","—"),
            ("5. Cifra con AES-256-GCM y firma sobre.","Recibe voto por HTTPS/TLS local.","—"),
            ("6. Recibe comprobante SHA-256.","Verifica padrón, firma, tag y voto único.","—"),
            ("—","Cierra, cuenta y firma el acta Ed25519.","Verifica acta con clave pública."),
        ]: tree.insert("","end",values=row)
        tree.pack(fill="both",expand=True,pady=12)
        ttk.Label(f,text="ECDH/HKDF/AES protegen la sesión; TLS protege el transporte; Ed25519 autentica servidor, votante y acta.",wraplength=950).pack(anchor="w")
    def _threat_tab(self) -> None:
        f=self.threats
        ttk.Label(f,text="Modelo de amenazas actualizado",style="Title.TLabel").pack(anchor="w")
        tree=ttk.Treeview(f,columns=("threat","control","limit"),show="headings",height=12)
        for col,title,width in [("threat","Amenaza",190),("control","Mitigación aplicada",430),("limit","Límite",340)]:
            tree.heading(col,text=title); tree.column(col,width=width,anchor="w")
        for row in [
            ("MITM / interceptación","TLS + X.509 fijado + firma del handshake ECDH.","Certificado local autosellado."),
            ("Suplantación del votante","Padrón habilitado + firma Ed25519.","Carteras generadas en memoria para la demo."),
            ("Alteración de voto","Firma Ed25519 + tag AES-GCM + HMAC-SHA-256.","No hay auditor externo/inmutable."),
            ("Doble voto / replay","Identidad usada una vez + sesión ECDH de un solo uso.","No existe recuperación ante fallos."),
            ("Acta falsa","Acta final firmada Ed25519, verificada con clave pública.","No hay CA externa."),
            ("Coerción / correlación","ID separado del registro de papeleta.","Sin anonimato criptográfico ni anti coerción."),
        ]: tree.insert("","end",values=row)
        tree.pack(fill="both",expand=True,pady=12)
        ttk.Label(f,text="La demo no es un sistema electoral real. No ingreses datos personales ni la uses en una elección oficial.",foreground="#9b3d34").pack(anchor="w")
    def example(self) -> None:
        self.org.set("Junta Vecinal Demo")
        self.roster.delete("1.0","end"); self.roster.insert("1.0","VEC-001, Ana de prueba\nVEC-002, Bruno de prueba\nVEC-003, Carla de prueba")
        self.candidates.delete("1.0","end"); self.candidates.insert("1.0","Lista Vecinal A\nLista Vecinal B\nVoto en blanco")
    def create(self) -> None:
        organization=self.org.get().strip()
        candidates=[x.strip() for x in self.candidates.get("1.0","end").splitlines() if x.strip()]
        lines=[x.strip() for x in self.roster.get("1.0","end").splitlines() if x.strip()]
        try:
            if self.active_role!="admin" or not self.admin_authenticated or not self.admin_verifier:
                raise ValueError("Solo el comité autenticado puede crear o modificar la elección.")
            if not organization: raise ValueError("Escribe el nombre de la organización.")
            if len(candidates)<2 or len(set(candidates))!=len(candidates): raise ValueError("Ingresa dos o más candidaturas distintas.")
            wallets={}
            access_codes={}
            for line in lines:
                parts=[x.strip() for x in line.split(",",1)]
                if len(parts)!=2 or not all(parts): raise ValueError(f"Formato incorrecto: {line}. Usa ID, Nombre.")
                if parts[0] in wallets: raise ValueError(f"ID repetido: {parts[0]}.")
                wallets[parts[0]]=VoterWallet(parts[0],ed25519.Ed25519PrivateKey.generate())
                access_codes[parts[0]]=secrets.token_urlsafe(6)
            if not wallets: raise ValueError("Ingresa al menos un votante.")
            if self.transport: self.transport.close()
            if self.tempdir: self.tempdir.cleanup()
            # En Windows administrado, el TEMP del sistema puede estar aislado y
            # no permitir que el servidor HTTPS cree sus archivos. Mantén el
            # certificado efímero en una carpeta temporal junto al prototipo.
            self.tempdir=tempfile.TemporaryDirectory(
                prefix=".voto_seguro_demo_", dir=Path(__file__).resolve().parent)
            server=ElectionServer(organization,candidates,{k:v.private_key.public_key() for k,v in wallets.items()})
            transport=LocalTLSServer(server,Path(self.tempdir.name))
            self.server,self.transport=server,transport
            self.client=VotingClient(transport,server,server.fingerprint)
            self.wallets=wallets
            self.voter_access_codes=access_codes
            # Cifrado de padrón de muestra. Clave aleatoria efímera, solo para esta sesión.
            rows=[{"id":line.split(",",1)[0].strip(),"nombre":line.split(",",1)[1].strip()} for line in lines]
            self.roster_packet=encrypt_roster(rows)
            self.choice_box["values"]=candidates
            codes="\n".join(f"{voter_id}    código: {code}" for voter_id,code in access_codes.items())
            self._set_text(self.codes_text,codes)
            self.pin_label.config(text="Huella X.509 SHA-256 fijada: "+server.fingerprint)
            self._log(f"Elección creada para {organization}; verificador PBKDF2-HMAC-SHA-256 protegido con 100,000 iteraciones y sal aleatoria.")
            self._log("Padrón cifrado AES-256-GCM. Servidor HTTPS/TLS activo en "+transport.url)
            self._log("Carteras Ed25519 y códigos de acceso de los votantes generados para esta sesión.")
            self.status.set(f"Elección abierta · {len(wallets)} votantes · HTTPS local")
            self.voter_access_button.config(state="normal")
            self.tabs.select(self.setup)
        except Exception as exc:
            messagebox.showerror("No se pudo crear la elección",str(exc))
    def ready(self) -> bool:
        if self.active_role!="admin" or not self.admin_authenticated:
            messagebox.showwarning("Acceso restringido","Esta acción pertenece al panel autenticado del comité.")
            return False
        if not self.server or not self.client:
            messagebox.showwarning("Falta configurar","Ve a Configurar y crea la elección.")
            return False
        return True
    def cast(self) -> None:
        if self.active_role!="voter" or not self.server or not self.client:
            messagebox.showwarning("Cabina no disponible","Regresa al inicio y entra por Cabina del votante.")
            return
        voter_id,choice=self.voter.get().strip(),self.choice.get().strip()
        pin=self.voter_pin.get().strip()
        if not voter_id or not pin or not choice:
            messagebox.showwarning("Completa los datos","Ingresa identificador, código privado y candidatura."); return
        expected_code=self.voter_access_codes.get(voter_id)
        if not expected_code or not hmac.compare_digest(pin,expected_code):
            messagebox.showerror("Identidad no validada","El identificador o código privado no es correcto.")
            self.voter_pin.delete(0,"end")
            return
        if not messagebox.askyesno("Confirmar voto",f"¿Enviar un voto cifrado para {voter_id}?"): return
        try:
            envelope,receipt=self.client.vote(self.wallets[voter_id],choice)
            self.last_envelope=envelope
            self.my_receipt.set("Voto aceptado · comprobante SHA-256: "+receipt)
            self._log("Voto recibido por HTTPS/TLS; ECDH, firma Ed25519 y AES-GCM válidos.")
            self.status.set("Voto cifrado, firmado y aceptado.")
            self.voter.set(""); self.choice.set("")
            self.voter_pin.delete(0,"end")
        except (ValueError,InvalidSignature) as exc:
            messagebox.showerror("Voto rechazado",str(exc)); self._log("RECHAZADO: "+str(exc))
    def verify_cert(self) -> None:
        if not self.ready(): return
        cert=self.server.certificate
        cert.public_key().verify(cert.signature,cert.tbs_certificate_bytes)
        self._log("Certificado X.509 y huella fijada coinciden. TLS verifica el certificado.")
        self._log("Es un certificado autosellado de la demo, no validado por una CA externa.")
        messagebox.showinfo("Certificado","Identidad válida para esta demo local; no es certificado de una CA pública.")
    def audit_votes(self) -> None:
        if not self.ready(): return
        ok,detail=self.server.audit()
        self._log(("AUDITORÍA OK: " if ok else "ALERTA: ")+detail)
        messagebox.showinfo("Auditoría",detail)
    def simulate_mitm(self) -> None:
        if not self.ready(): return
        fake=VotingClient(self.transport,self.server,"00"*32)
        try: fake.vote(next(iter(self.wallets.values())),self.server.candidates[0])
        except ValueError as exc:
            self._log("MITM DETECTADO: "+str(exc)); messagebox.showinfo("MITM detectado",str(exc))
    def simulate_tamper(self) -> None:
        if not self.ready(): return
        if not self.last_envelope:
            messagebox.showwarning("Sin voto","Emite un voto antes de simular alteración."); return
        tampered=dict(self.last_envelope); tampered["ciphertext_tag"]=b64(b"voto alterado")
        try: self.client.post("/vote",tampered)
        except ValueError as exc:
            self._log("ALTERACIÓN DETECTADA: "+str(exc)); messagebox.showinfo("Alteración detectada",str(exc))
    def close_election(self) -> None:
        if not self.ready(): return
        if not self.server.open:
            messagebox.showinfo("Elección cerrada","Ya se generó el acta."); return
        if not messagebox.askyesno("Cerrar elección","¿Cerrar los votos y firmar el acta?"): return
        try:
            minutes,signature=self.server.close_and_sign()
            self.server.certificate.public_key().verify(unb64(signature),json_bytes(minutes))
            text=json.dumps({"acta":minutes,"firma_ed25519_base64":signature},ensure_ascii=False,indent=2)
            self._set_text(self.minutes,text)
            self._log("Acta cerrada y firmada Ed25519; firma verificada con la clave pública X.509.")
            self.voter_access_button.config(state="disabled")
            self.status.set("Elección cerrada · acta firmada y verificada")
            messagebox.showinfo("Acta","Acta generada y firma verificada.")
        except (ValueError,InvalidSignature) as exc: messagebox.showerror("Error al cerrar",str(exc))
    def _log(self,text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end",f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n")
        self.log.see("end"); self.log.configure(state="disabled")
    @staticmethod
    def _set_text(widget: tk.Text,text: str) -> None:
        widget.configure(state="normal"); widget.delete("1.0","end")
        widget.insert("1.0",text); widget.configure(state="disabled")
    def close(self) -> None:
        if self.transport: self.transport.close()
        if self.tempdir: self.tempdir.cleanup()
        self.root.destroy()

def main() -> None:
    root=tk.Tk()
    VotingGUI(root)
    root.mainloop()

if __name__=="__main__":
    main()
