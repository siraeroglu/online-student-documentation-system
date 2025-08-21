from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# DES Şifreleme
def encrypt_des(key, plaintext):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
    encryptor = cipher.encryptor()
    padded_text = plaintext + (8 - len(plaintext) % 8) * " "
    return encryptor.update(padded_text.encode())

def decrypt_des(key, ciphertext):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext).decode().strip()

# RSA İmza ve Doğrulama
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_with_rsa(private_key, message):
    return private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_rsa_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
