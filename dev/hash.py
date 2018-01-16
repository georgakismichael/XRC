import scrypt
import uuid

test_hash = False

if test_hash:
    h1 = scrypt.hash('password', 'random salt', N=1<<18, r=8, p=4, buflen=64)
    print h1
    print len(h1)

    h2 = scrypt.hash('password', 'random salt', N=1<<18, r=8, p=4, buflen=64)
    print h2
    print len(h2)

    if h1 == h2:
        print 'same'
    else:
        print 'no match'
        
SCRY_N = 1<<18
SCRY_R = 16
SCRY_P = 8
SCRY_MIN_SALT_SZ = 16
SCRY_MIN_BUF_SZ = 256

def hash_password(password, maxtime=0.5, datalength=64):
    return scrypt.encrypt(os.urandom(datalength), password, maxtime=maxtime)

def verify_password(hashed_password, guessed_password, maxtime=0.5):
    try:
        scrypt.decrypt(hashed_password, guessed_password, maxtime)
        return True
    except scrypt.error:
        return False
        
def generate_key(passphrase, saltlen):
    """Generate a new key."""
    if saltlen < SCRY_MIN_SALT_SZ:
        raise Exception("Salt is too short (" + str(saltlen) + ")")
    pre_salt = uuid.uuid4().hex
    if len(pre_salt) <= saltlen:
        print ("Limiting salt size to " + str(len(pre_salt)))
        salt = pre_salt
    else:
        salt = pre_salt[saltlen:]
    key = scrypt.hash(passphrase, salt, N=SCRY_N, r=SCRY_R, p=SCRY_P, buflen=SCRY_MIN_BUF_SZ)
    return key, salt
  
  
def restore_key(passphrase, salt):
    """Restore a key from passphrase and salt."""
    if len(salt) < SCRY_MIN_SALT_SZ:
        raise Exception("Salt is too short (" + str(saltlen) + ")")
    return scrypt.hash(passphrase, salt, N=SCRY_N, r=SCRY_R, p=SCRY_P, buflen=SCRY_MIN_BUF_SZ)
    
    
key_, salt_ = generate_key('passphrase', 32)

print key_
print salt_

hash_ = restore_key('passphrase', salt_)

print hash_