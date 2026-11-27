"""Shared helpers: X25519 key exchange + HKDF + AES-256-GCM."""
import os

from cryptography.exceptions import InvalidTag  # re-exported for the scripts
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

KEY_LEN = 32    # 32 bytes = 256 bits -> AES-256
IV_LEN = 12     # 12 bytes = standard GCM nonce size
SALT_LEN = 16   # 16 bytes = standard salt size


# ---------- 1. Key pairs (X25519) ----------
def generate_keypair():
    private = X25519PrivateKey.generate()
    return private, private.public_key()


def public_to_hex(public_key) -> str:
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def public_from_hex(hex_str: str) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(bytes.fromhex(hex_str.strip()))


# ---------- 2. Key derivation (HKDF) ----------
def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def hkdf(secret: bytes, salt: bytes, label: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=label,          # different label = different, independent key
    ).derive(secret)


def derive_session_keys(shared_secret: bytes, salt: bytes) -> dict:
    """One shared secret -> 2 keys + 2 IVs (one pair per direction)."""
    return {
        "client_key": hkdf(shared_secret, salt, b"client key", KEY_LEN),
        "server_key": hkdf(shared_secret, salt, b"server key", KEY_LEN),
        "client_iv":  hkdf(shared_secret, salt, b"client iv", IV_LEN),
        "server_iv":  hkdf(shared_secret, salt, b"server iv", IV_LEN),
    }


# ---------- 3. Encryption (AES-GCM) ----------
def make_nonce(iv: bytes, seq: int) -> bytes:
    """nonce = IV XOR sequence number (same idea as TLS 1.3)."""
    return (int.from_bytes(iv, "big") ^ seq).to_bytes(IV_LEN, "big")


class Session:
    """Holds the keys for one side and counts messages in each direction."""

    def __init__(self, send_key, send_iv, recv_key, recv_iv):
        self.send_key, self.send_iv = send_key, send_iv
        self.recv_key, self.recv_iv = recv_key, recv_iv
        self.send_seq = 0
        self.recv_seq = 0

    def send(self, text: str) -> str:
        nonce = make_nonce(self.send_iv, self.send_seq)
        ct = AESGCM(self.send_key).encrypt(nonce, text.encode(), None)
        self.send_seq += 1
        return ct.hex()                      # ciphertext + 16-byte tag

    def receive(self, hex_str: str) -> str:
        nonce = make_nonce(self.recv_iv, self.recv_seq)
        ct = bytes.fromhex(hex_str.strip())
        pt = AESGCM(self.recv_key).decrypt(nonce, ct, None)   # raises InvalidTag
        self.recv_seq += 1                   # only counts if decryption worked
        return pt.decode()


def make_session(role: str, keys: dict) -> Session:
    """Client sends with the client key; server sends with the server key."""
    if role == "client":
        return Session(keys["client_key"], keys["client_iv"],
                       keys["server_key"], keys["server_iv"])
    return Session(keys["server_key"], keys["server_iv"],
                   keys["client_key"], keys["client_iv"])


# ---------- 4. Small helpers for the demo scripts ----------
def show_secrets(shared_secret: bytes, keys: dict) -> None:
    print("\n[DEMO ONLY - never print secrets in a real app]")
    print(f"{'shared secret':<12}: {shared_secret.hex()}")
    for name, value in keys.items():
        print(f"{name:<12}: {value.hex()}")


def chat_loop(session: Session, name: str) -> None:
    print("\nCommands:  s = send   r = receive   q = quit")
    while True:
        cmd = input(f"\n{name}> ").strip().lower()

        if cmd == "s":
            text = input("Message: ")
            seq = session.send_seq
            nonce = make_nonce(session.send_iv, seq).hex()
            blob = session.send(text)
            print(f"  seq={seq}  nonce={nonce}")
            print(f"  Send this to the other side:\n  {blob}")

        elif cmd == "r":
            blob = input("Paste ciphertext (hex): ")
            try:
                print("  Decrypted:", session.receive(blob))
            except InvalidTag:
                print("  REJECTED: wrong key, tampered, replayed or out of order")
            except ValueError:
                print("  That is not valid hex")

        elif cmd == "q":
            break