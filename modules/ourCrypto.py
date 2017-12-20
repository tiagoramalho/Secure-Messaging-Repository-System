import os
from os import path
import sys
import base64
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac




ENCODING = "utf-8"

def sendPubKey(key):
    myPubKey = key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)    
    return base64.b64encode(myPubKey).decode(ENCODING)

def recvPubKey(key):
    pubKey =  base64.b64decode(key.encode(ENCODING))
    pubKey = load_pem_public_key(pubKey, backend=default_backend())
    return pubKey

def sendBytes(hashS):
    return base64.b64encode(hashS).decode(ENCODING)

def recvBytes(hashS):
    return base64.b64decode(hashS.encode(ENCODING))

def verifyHash(index, previousHash, data, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    value = str(index) + str(previousHash) + str(data)
    h.update(value.encode('utf-8'))
    newHash = h.finalize()
    return newHash

def randomMsgId():
    return int.from_bytes(os.urandom(16), byteorder="big")

