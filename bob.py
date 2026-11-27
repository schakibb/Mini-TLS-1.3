from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import os

# Cuz we r gonna use AES256_GCM (32*8=256)
salt=os.urandom(32)

bob=x25519.X25519PrivateKey.generate()
bob_public_key=bob.public_key()

public_pairs={
    "salt":salt.hex(),
    "public_key":bob_public_key.public_bytes(encoding=Encoding.Raw,format=PublicFormat.Raw).hex()
}



print(public_pairs)

print('-'*30)


alice_public_key_hex=input("Enter Alice Public Key: ")
alice_public_key_Bytes=bytes.fromhex(alice_public_key_hex)
alice_public_key=x25519.X25519PublicKey.from_public_bytes(alice_public_key_Bytes)


shared_secret=bob.exchange(alice_public_key)


print('The shared secret is: ',shared_secret.hex())