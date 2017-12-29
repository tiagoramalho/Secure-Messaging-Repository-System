import json
import os
from os import path
import sys
from log import *

sys.path.append(path.join(path.dirname(path.realpath(__file__)),'../modules/'))
from BlockChain import Block 
from cc_interection import Certificate
import ourCrypto

ENCODING = 'utf-8'
TERMINATOR = "\r\n"
BUFSIZE = 512 * 1024

def sessionConnect(client):
    randomID = ourCrypto.randomMsgId() 
    payload = {"status" : 1, "randomID" : randomID} 
    signature = client.cc.sign(json.dumps(payload, sort_keys = True))
    message = { 'type'	: 'session', 
                'payload'	: payload,
                'signed' : ourCrypto.sendBytes(signature),
                'cert' : ourCrypto.sendBytes(client.cc.cert.dump_certificate()),
              }

    client.send_to_server(message)

    response = json.loads(client.socket.recv(BUFSIZE).decode('utf-8'))
    #verificar assinatura e se os randomMsgId sao iguais
    valido = False
    try:
        client.certCertificate = Certificate(ourCrypto.recvBytes(response["result"]["cert"]))

        log_info("Validation of the server signature.")
        valido = client.certCertificate.validate_signature(json.dumps(response["result"]["payload"], sort_keys =True), ourCrypto.recvBytes(response["result"]["signed"]), False)
            
    except Exception as e:
        log_error("Session was not established, try again")
        return False

    
    if valido:
        try:
            log_error(response["result"]["payload"]["error"])
            return False
        except Exception as e:
            pass

        if randomID == response["result"]["payload"]["randomID"]:
            client.sessionKeys.getSecret(ourCrypto.recvPubKey(response["result"]["payload"]["pubKey"]))
        else:
            log_error("Session was not established")
            return False


    payload = {"status" : 2, "pubKey" : ourCrypto.sendPubKey(client.sessionKeys.pubKey)}

    key, salt = client.sessionKeys.deriveShared()
    payload["salt"] = ourCrypto.sendBytes(salt)

    hashS = ourCrypto.generate_hash(0, '0', json.dumps(payload, sort_keys = True), key)
    
    client.blockChain = Block(0, '0',payload, hashS) 
    payload["hash"] = ourCrypto.sendBytes(hashS)
    signature = client.cc.sign(json.dumps(payload, sort_keys = True))
    message = { 'type'	: 'session', 
                'payload'	: payload,  
                'signed' : ourCrypto.sendBytes(signature),
                'cert' : ourCrypto.sendBytes(client.cc.cert.dump_certificate()),
              }
    client.send_to_server(message)

    response = json.loads(client.socket.recv(BUFSIZE).decode('utf-8'))

    try:
        log_error(response["result"]["payload"]["error"])
    except Exception as e:
        pass

    hashS = ourCrypto.recvBytes(response["result"]["hash"])
    del response["result"]["hash"]
    salt = ourCrypto.recvBytes(response["result"]["salt"])
    key, salt = client.sessionKeys.deriveShared(salt)
    if hashS == client.blockChain.isNextBlock(json.dumps(response["result"], sort_keys = True),key):
        client.blockChain.createNext(hashS)
        log_success("Session successfully established.")
        return True
    else:
        log_error("Session was not established.")
        return False

