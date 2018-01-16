import base64
from Crypto.Cipher import AES
from Crypto import Random
import hashlib

BLOCK_SIZE=16
tststr = 'aa00000000000200q'

def HexToByte( hexStr ):
    """
    Convert a string hex byte values into a byte string. The Hex Byte values may
    or may not be space separated.
    """
    # The list comprehension implementation is fractionally slower in this case    
    #
    #    hexStr = ''.join( hexStr.split(" ") )
    #    return ''.join( ["%c" % chr( int ( hexStr[i:i+2],16 ) ) \
    #                                   for i in range(0, len( hexStr ), 2) ] )
 
    bytes = []

    hexStr = ''.join( hexStr.split(" ") )

    for i in range(0, len(hexStr), 2):
        bytes.append( chr( int (hexStr[i:i+2], 16 ) ) )

    return ''.join( bytes )

hash_object = hashlib.sha256(b'This is a key123')
hex_dig = hash_object.hexdigest()
key256 = HexToByte(hex_dig)

def pad_as_necessary(inp):
	if len(inp)%BLOCK_SIZE != 0:
		pad_size = BLOCK_SIZE - len(inp)%BLOCK_SIZE
		pad_string = ''
		for i in range(0, pad_size):
			pad_string += '0'
		ret = inp+pad_string		
	else:
		ret = inp
	return str(ret)

# Encryption
IV = Random.new().read(BLOCK_SIZE)
encryption_suite = AES.new(key256, AES.MODE_CBC, IV)
#cipher_text = encryption_suite.encrypt(pad_as_necessary(tststr))
cipher_text = base64.b64encode(IV + encryption_suite.encrypt(pad_as_necessary(tststr)))

enc = base64.b64decode(cipher_text)
iv = enc[:BLOCK_SIZE]
cipher = AES.new(key256, AES.MODE_CBC, iv )
plain_text = cipher.decrypt( enc[BLOCK_SIZE:] )

assert pad_as_necessary(tststr) == plain_text
