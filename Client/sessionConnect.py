import json
import os
from os import path
import sys

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
    try:
        client.certCertificate = Certificate(ourCrypto.recvBytes(response["result"]["cert"]))
        valido = client.certCertificate.validate_signature(json.dumps(response["result"]["payload"], sort_keys =True), ourCrypto.recvBytes(response["result"]["signed"]))
        print(valido)
        if randomID == response["result"]["payload"]["randomID"]:
            client.sessionKeys.getSecret(ourCrypto.recvPubKey(response["result"]["payload"]["pubKey"]))
        else:
            print("rando id errado")
    except Exception as e:
        print(e)


    payload = {"status" : 2, "pubKey" : ourCrypto.sendPubKey(client.sessionKeys.pubKey)}
    #        client.sessionKeys.pubKey
    key, salt = client.sessionKeys.deriveShared()
    payload["salt"] = ourCrypto.sendBytes(salt)

    hashS = ourCrypto.verifyHash(0, '0', json.dumps(payload, sort_keys = True), key)
    client.blockChain = Block(0, '0',payload, hashS) 
    payload["hash"] = ourCrypto.sendBytes(hashS)
    signature = client.cc.sign(json.dumps(payload, sort_keys = True))
    message = { 'type'	: 'session', 
                'payload'	: payload,  
                'signed' : ourCrypto.sendBytes(signature),
                'cert' : ourCrypto.sendBytes(client.cc.cert.dump_certificate()),
              }
    client.send_to_server(message)
    #Ultima resposta proveniente do servidor para troca de chaves
    #tem de gerar a mesma hash do ack

    response = json.loads(client.socket.recv(BUFSIZE).decode('utf-8'))
    print(response)

    hashS = ourCrypto.recvBytes(response["result"]["hash"])
    del response["result"]["hash"]
    salt = ourCrypto.recvBytes(response["result"]["salt"])
    key, salt = client.sessionKeys.deriveShared(salt)
    print("result")
    if hashS == client.blockChain.isNextBlock(json.dumps(response["result"], sort_keys = True),key):
        client.blockChain.createNext(json.dumps(response["result"], sort_keys = True), hashS)
        print("sessão estabelecida e blockChain gerada")
    else:
        print("puta")
    return True
