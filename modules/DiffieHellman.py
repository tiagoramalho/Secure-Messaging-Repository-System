#from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives.asymmetric import dh
#import os
#from cryptography.hazmat.primitives import hashes
#from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
#from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec



class DiffieHellman(object):
    def __init__(self):
        self.privKey = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.pubKey = self.privKey.public_key()
        self.sharedKey = None

    def getSecret(self, peer_public_key):
        self.sharedKey = self.privKey.exchange(ec.ECDH(), peer_public_key)

    def renovateSecret(self, peer_public_key):
        self.privKey = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.pubKey = self.privKey.public_key()
        self.sharedKey = self.privKey.exchange(ec.ECDH(), peer_public_key)

if __name__ == "__main__":
    
    v = DiffieHellman()
    s = DiffieHellman()
    v.getSecret(s.pubKey)
    s.getSecret(v.pubKey)
    
    if s.sharedKey == v.sharedKey:
        print("OK")
    #pemA = pubA.public_bytes(encoding=serialization.Encoding.PEM, 
    #        format=serialization.PublicFormat.SubjectPublicKeyInfo
    #)
