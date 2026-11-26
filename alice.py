from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

alice=x25519.X25519PrivateKey.generate()
alice_public_key=alice.public_key()

print(alice_public_key.public_bytes(encoding=Encoding.Raw,format=PublicFormat.Raw).hex())

print('-'*30)

bob_public_key_hex=input("Enter Bobs Public Key: ")
bob_public_key_Bytes=bytes.fromhex(bob_public_key_hex)
bob_public_key=x25519.X25519PublicKey.from_public_bytes(bob_public_key_Bytes)

shared_secret=alice.exchange(bob_public_key)

print('The shared ssecret is: ',shared_secret.hex())