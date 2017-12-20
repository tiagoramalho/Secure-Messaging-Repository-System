import json
import os
from os import path
import sys

sys.path.append(path.join(path.dirname(path.realpath(__file__)),'../modules/'))
from BlockChain import Block 
import ourCrypto

ENCODING = 'utf-8'
TERMINATOR = "\r\n"
BUFSIZE = 512 * 1024

def sessionConnect(client):
    randomID = ourCrypto.randomMsgId() 
    msg = {"status" : 1, "randomID" : randomID} 
    signature = client.cc.sign(json.dumps(msg, sort_keys = True))
    message = { 'type'	: 'session', 
                'msg'	: msg,  
                'signed'	: signature,
                'cert' : client.cc.get_my_cert()
              }

    client.send_to_server(message)
    response = json.loads(client.socket.recv(BUFSIZE).decode('utf-8'))
    #verificar assinatura e se os randomMsgId sao iguais
    client.sessionKeys.getSecret(ourCrypto.recvPubKey(response["result"]["pubKey"]))


    msg = {"status" : 2, "pubKey" : ourCrypto.sendPubKey(client.sessionKeys.pubKey)}
    #        client.sessionKeys.pubKey
    key, salt = client.sessionKeys.deriveShared()
    msg["salt"] = ourCrypto.sendBytes(salt)

    hashS = ourCrypto.verifyHash(0, '0', json.dumps(msg, sort_keys = True), key)
    client.blockChain = Block(0, '0',msg, hashS) 
    message = { 'type'	: 'session', 
                'msg'	: msg,  
                'signed'	: "assinatura da msg",
                'hash'      : ourCrypto.sendBytes(hashS),
              }
    client.send_to_server(message)
    response = json.loads(client.socket.recv(BUFSIZE).decode('utf-8'))
    print(response)
    return True
