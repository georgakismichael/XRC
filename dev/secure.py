from Crypto import Random
from Crypto.Cipher import AES
import base64
import hmac
from hashlib import sha1
import hashlib

passwd_enc = 'mysecretencpassword'
passwd_sign = 'mysecretsignpassword'

block_sz = 16
pad = lambda s: s + (block_sz - len(s) % block_sz) * chr(block_sz - len(s) % block_sz)
unpad = lambda s : s[0:-ord(s[-1])]

def encrypt(key_encrypt, dec):
    if dec is None or len(dec) == 0:
        raise ValueError("No value given to encrypt")
    key_encrypt = hashlib.sha256(key_encrypt.encode()).digest()
    dec = pad(dec)
    iv = Random.new().read( AES.block_size )
    cipher = AES.new(key_encrypt, AES.MODE_CBC, iv)
    return base64.b64encode( iv + cipher.encrypt( dec ) )

def decrypt(key_encrypt, enc):
    key_encrypt = hashlib.sha256(key_encrypt.encode()).digest()
    enc = base64.b64decode(enc)
    iv = enc[:block_sz]
    cipher = AES.new(key_encrypt, AES.MODE_CBC, iv )
    return unpad(cipher.decrypt( enc[block_sz:] ))
    
def create_signature(key_sign, msg):
    key_sign = hashlib.sha256(key_sign.encode()).digest()
    msg_to_sign = msg.encode('utf-8')
    hashed = hmac.new(key_sign, msg_to_sign, sha1)
    return hashed.hexdigest()
    



