from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

bob=x25519.X25519PrivateKey.generate()
bob_public_key=bob.public_key()



print(bob_public_key.public_bytes(encoding=Encoding.Raw,format=PublicFormat.Raw).hex())

print('-'*30)


alice_public_key_hex=input("Enter Alice Public Key: ")
alice_public_key_Bytes=bytes.fromhex(alice_public_key_hex)
alice_public_key=x25519.X25519PublicKey.from_public_bytes(alice_public_key_Bytes)


shared_secret=bob.exchange(alice_public_key)


print('The shared secret is: ',shared_secret.hex())