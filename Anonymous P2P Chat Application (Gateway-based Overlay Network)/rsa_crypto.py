from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def load_public_key(path="my_public.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def load_private_key(path="my_private.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def encrypt_message(message: str, public_key):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def decrypt_message(encrypted: bytes, private_key):
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()


def get_public_key_string():
    with open("my_public.pem", "rb") as f:
        return f.read().decode()



def load_public_key_from_pem(pem_data: bytes):
    return serialization.load_pem_public_key(pem_data, backend=default_backend())
