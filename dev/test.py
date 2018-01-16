# This is for Python 2
from hashlib import sha1
import hmac

import base64
from Crypto import Random
from Crypto.Cipher import AES

import math

import uuid
import hashlib
 


secret_key_signature = ''
string_ = ''
cipher = 'mysecretpassword'

block_sz = 16
pad = lambda s: s + (block_sz - len(s) % block_sz) * chr(block_sz - len(s) % block_sz)
unpad = lambda s : s[0:-ord(s[-1])]

def create_password(secret_key, passwd):
    hashed = hmac.new(secret_key, passwd, sha256)
    return hashed.hexdigest()

def create_signature(secret_key, string):
    string_to_sign = string.encode('utf-8')
    hashed = hmac.new(secret_key, string_to_sign, sha1)
    return hashed.hexdigest()
    
def encrypt(key, dec):
    if dec is None or len(dec) == 0:
        raise ValueError("No value given to encrypt")
    dec = pad(dec)
    iv = Random.new().read( AES.block_size )
    cipher = AES.new(key, AES.MODE_CBC, iv )
    return base64.b64encode( iv + cipher.encrypt( dec ) )

def decrypt(key, enc):
    enc = base64.b64decode(enc)
    iv = enc[:block_sz]
    cipher = AES.new(key, AES.MODE_CBC, iv )
    return unpad(cipher.decrypt( enc[block_sz:] ))
    
def entropy(string):
    "Calculates the Shannon entropy of a string"
    # get probability of chars in string
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    # calculate the entropy
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy

def hash_password(password):
    # uuid is used to generate a random number
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt
    
def check_password(hashed_password, user_password):
    password, salt = hashed_password.split(':')
    return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()
    
new_pass = raw_input('Please enter a password: ')
hashed_password = hash_password(new_pass)
print('The string to store in the db is: ' + hashed_password + ' with size: ' + str(len(hashed_password)))
    
print create_signature(secret_key_signature, string_)

encrypted = encrypt(cipher, 'Secret Message A')
print encrypted

decrypted = decrypt(cipher, encrypted)
print decrypted

print entropy(encrypted)
print entropy(decrypted)
 
old_pass = raw_input('Now please enter the password again to check: ')
if check_password(hashed_password, old_pass):
    print('You entered the right password')
else:
    print('I am sorry but the password does not match')