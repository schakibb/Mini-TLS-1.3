from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

# Cuz we r gonna use AES256_GCM (32*8=256)
salt=b'40d771cffa7d169c540fc061ff877bbc'

def derive_key(label:str,len:int,salt:bytes,secret:bytes):
    return HKDF(algorithm=hashes.SHA256(),
                     length=len,
                     salt=salt,
                     info=label).derive(secret)
    


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


derived_key1=derive_key(b'Server key',len=32,salt=salt,secret=shared_secret)
derived_key2=derive_key(b'Client key',len=32,salt=salt,secret=shared_secret)
derived_key3=derive_key(b'Client IV',len=12,salt=salt,secret=shared_secret)
derived_key4=derive_key(b'Client IV',len=12,salt=salt,secret=shared_secret)

print(derived_key1.hex())
print(derived_key2.hex())
print(derived_key3.hex())
print(derived_key4.hex())