"""Núcleo criptográfico: ECDH + HKDF + AES-256-GCM + Ed25519 + X.509 + TLS local."""
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
