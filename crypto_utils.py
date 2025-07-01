from Crypto.Cipher import DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
import math
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad

def encrypt_des3_with_iv(data, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_data = pad(data, DES3.block_size)
    encrypted = cipher.encrypt(padded_data)
    return encrypted

def split_file(data, parts=3):
    size = len(data)
    chunk_size = math.ceil(size / parts)
    chunks = [data[i*chunk_size:(i+1)*chunk_size] for i in range(parts)]
    return chunks

def encrypt_des3(data, key):
    cipher = DES3.new(key, DES3.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

def decrypt_des3(data, key):
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = DES3.new(key, DES3.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def rsa_encrypt(data, public_key):
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA512)
    return cipher.encrypt(data)

def rsa_decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA512)
    return cipher.decrypt(ciphertext)

def sha512_hash(data):
    h = SHA512.new(data)
    return h.digest()

def rsa_sign(data, private_key):
    h = SHA512.new(data)
    signer = pkcs1_15.new(private_key)
    return signer.sign(h)

def rsa_verify(data, signature, public_key):
    h = SHA512.new(data)
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(h, signature)
        return True
    except:
        return False
