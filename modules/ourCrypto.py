import os
from os import path
import sys
import base64
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac

from symmetric import Sym_Cyphers 
from DiffieHellman import DiffieHellman
import json




ENCODING = "utf-8"

def sendPubKey(key):
    myPubKey = key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)    
    return base64.b64encode(myPubKey).decode(ENCODING)

def recvPubKey(key):
    pubKey =  base64.b64decode(key.encode(ENCODING))
    pubKey = load_pem_public_key(pubKey, backend=default_backend())
    return pubKey

def sendBytes(hashS):
    if isinstance(hashS, int): return hashS 
    if isinstance(hashS, str):
        return base64.b64encode(bytes(hashS, 'utf-8')).decode(ENCODING)
    if isinstance(hashS, list):
        ls = []
        for value in hashS:
            ls.append(sendBytes(value))
        return ls
    if isinstance(hashS, dict):
        dic = {}
        for key, value in hashS.items():
            dic[key] = sendBytes(value)
        return dic

    return base64.b64encode(hashS).decode(ENCODING)

def recvBytes(hashS):
    if isinstance(hashS, int):
        return hashS

    if isinstance(hashS, list):
        ls = []
        for value in hashS:
            ls.append(recvBytes(value))
        return ls
    if isinstance(hashS, dict):
        dic = {}
        for key, value in hashS.items():
            dic[key] = recvBytes(value)
        return dic

    return base64.b64decode(hashS.encode(ENCODING))


def get_bytes(hashS):
    if isinstance(hashS, bytes):
        try:
            return base64.b64decode(hashS).decode(ENCODING)
        except Exception as e:
            return hashS.decode("utf-8") 

    elif isinstance(hashS, dict):
        dic = {}
        for key, value in hashS.items():
            dic[key] = get_bytes(value)
        return dic
    elif isinstance(hashS, list):
        ls = []
        for value in hashS:
            ls.append(get_bytes(value))
        return ls
    return hashS



def generate_hash(index, previousHash, data, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    value = str(index) + str(previousHash) + str(data)
    h.update(value.encode('utf-8'))
    newHash = h.finalize()
    return newHash

def randomMsgId():
    return int.from_bytes(os.urandom(16), byteorder="big")


def generate_integrity(payload, dh_object, block_chain):

    encriptMsg, iv, salt = cypherSession(json.dumps(payload, sort_keys = True), dh_object)
    payload = {"payload" : encriptMsg, "iv" : iv, "salt" : salt}
    key, salt = dh_object.deriveShared()
    payload = sendBytes(payload)
    block_chain.generateNextBlock(json.dumps(payload, sort_keys =True), key)

    return {
        "payload": payload,
        "salt": sendBytes(salt),
        "hash": sendBytes(block_chain.currentHash),
    }, block_chain



def verify_integrity(data, dh_object, block_chain):
    salt = recvBytes(data["salt"])
    phash = recvBytes(data["hash"])


    key, salt = dh_object.deriveShared(salt) 
    payload = data["payload"] 

    nhash = block_chain.isNextBlock(json.dumps(payload, sort_keys =True), key)

    if nhash == phash:
        block_chain.createNext(nhash)
        payload = recvBytes(payload)
        payload = json.loads(decypherSession(payload["payload"], dh_object, payload["salt"],payload["iv"]))
        

        return True, block_chain, {"payload": payload}

    else:
        return False, block_chain, None

def load_payload(payload):
    for key, value in payload.items():
        if key != "type":
            payload[key] = sendBytes(value)
    return payload

def unload_payload(payload):

    if isinstance(payload, list):
        ls = []
        for value in payload:
            ls.append(recvBytes(value))
        return ls

    for key, value in payload.items():
        if key != "type":
            payload[key] = recvBytes(value)
    return payload

def cypherSession(msg, dh_object):
    iv = os.urandom(16)
    key, salt = dh_object.deriveShared()
    sessionCyph = Sym_Cyphers(key=key, iv=iv)
    encriptMsg = sessionCyph.cyph_text(msg.encode(ENCODING))

    return encriptMsg, iv, salt

def decypherSession(msg, dh_object, salt, iv):

    key, salt = dh_object.deriveShared(salt) 
    sessionCyph = Sym_Cyphers(key=key, iv=iv)
    decriptMsg = sessionCyph.decyph_text(msg)
    return get_bytes(decriptMsg)


