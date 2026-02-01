import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Random import get_random_bytes


class CryptoSession:
    def __init__(self):
        self._rsa = RSA.generate(2048)
        self._rsa_private = self._rsa
        self._rsa_public_b64 = base64.b64encode(
            self._rsa.publickey().export_key(format='DER')
        ).decode()

        self._aes_key = None

    # ===== RSA =====

    def get_public_key_frame(self):
        return b'PUB|' + self._rsa_public_b64.encode()

    def receive_encrypted_aes(self, encrypted_key):
        cipher = PKCS1_v1_5.new(self._rsa_private)
        self._aes_key = cipher.decrypt(encrypted_key, None)
        return self._aes_key is not None

    # ===== AES-GCM =====

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = get_random_bytes(12)
        cipher = AES.new(self._aes_key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return iv + ciphertext + tag

    def decrypt(self, payload: bytes) -> bytes:
        iv = payload[:12]
        ciphertext = payload[12:-16]
        tag = payload[-16:]

        cipher = AES.new(self._aes_key, AES.MODE_GCM, nonce=iv)
        return cipher.decrypt_and_verify(ciphertext, tag)

    @property
    def ready(self):
        return self._aes_key is not None
