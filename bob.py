from crypto_utils import (
    chat_loop, derive_session_keys, generate_keypair, make_session,
    public_from_hex, public_to_hex, show_secrets,
)

print("=== BOB (responder) ===")

private, public = generate_keypair()

print("\nSend this to Alice (public, safe to share):")
print("  public key :", public_to_hex(public))

salt = bytes.fromhex(input("\nPaste Alice's salt: ").strip())
alice_public = public_from_hex(input("Paste Alice's public key: "))

shared_secret = private.exchange(alice_public)
keys = derive_session_keys(shared_secret, salt)
show_secrets(shared_secret, keys)

chat_loop(make_session("server", keys), "Bob")