from Crypto.Protocol.KDF import scrypt
from secrets import token_bytes
from Crypto.Cipher import AES


def key_creation():
    salt = str(token_bytes(16))
    b_password = str(token_bytes(16))
    key = scrypt(b_password, salt, 16, N=2 ** 14, r=8, p=1)
    return key


def encryption(en_key, data):
    cipher = AES.new(en_key, AES.MODE_EAX)
    nonce_f = cipher.nonce
    ciphertext_f, tag_f = cipher.encrypt_and_digest(data)
    return nonce_f, tag_f, ciphertext_f


def decryption(de_key_f, nonce_f, tag_f, ciphertext_f):
    # decryption process
    cipher = AES.new(de_key_f, AES.MODE_EAX, nonce=nonce_f)
    plaintext_f = cipher.decrypt(ciphertext_f)
    try:
        cipher.verify(tag_f)
        return plaintext_f
    except ValueError:
        return b'Password error'


def pad(text):
    padded_password = text+b'\0' * (AES.block_size - len(text) % AES.block_size)
    return padded_password
