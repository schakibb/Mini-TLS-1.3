from crypto_utils import (
    chat_loop, derive_session_keys, generate_keypair, make_session,
    new_salt, public_from_hex, public_to_hex, show_secrets,
)

print("=== ALICE (initiator) ===")

private, public = generate_keypair()
salt = new_salt()                       # the initiator picks the salt

print("\nSend these to Bob (public, safe to share):")
print("  salt       :", salt.hex())
print("  public key :", public_to_hex(public))

bob_public = public_from_hex(input("\nPaste Bob's public key: "))

shared_secret = private.exchange(bob_public)
keys = derive_session_keys(shared_secret, salt)
show_secrets(shared_secret, keys)

chat_loop(make_session("client", keys), "Alice")