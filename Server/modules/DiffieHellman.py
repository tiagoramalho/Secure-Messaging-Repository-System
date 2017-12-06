from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization

p=0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
pn = dh.DHParameterNumbers(p, g)
parameters = pn.parameters(default_backend())
salt = os.urandom(16)

def getPrivateKey():
    private_key = parameters.generate_private_key()
    return private_key

if __name__ == "__main__":
    
    privA = getPrivateKey()
    pubA = privA.public_key()
    print(type(pubA))
    print(type(privA))
    pemA = pubA.public_bytes(encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    privB = getPrivateKey()
    pubB = privB.public_key()
    pemB = pubB.public_bytes(encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if pubA == pubB: 
        print("sao iguais")
    
    sharedA = privA.exchange(pubB)
    sharedB = privB.exchange(pubA)

    if sharedA == sharedB: 
        print("shared sao iguais")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
        )
    keyA = kdf.derive(sharedA)
    print(keyA)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
        )
    keyB = kdf.derive(sharedA)
    print(keyB)
