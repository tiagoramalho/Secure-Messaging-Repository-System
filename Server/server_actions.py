#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from log import *
from server_registry import *
from server_client import *
import json
import base64
import os
from os import path
import sys

sys.path.append(path.join(path.dirname(path.realpath(__file__)),'../modules/'))
from DiffieHellman import DiffieHellman
from BlockChain import Block 
from cc_interection import Certificate
import ourCrypto
from ourCrypto import sendBytes
from ourCrypto import recvBytes
from ourCrypto import unload_payload
from ourCrypto import load_payload
from ourCrypto import get_bytes 




from pprint import pprint

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend

ENCODING = 'utf-8'
class ServerActions:
    def __init__(self):

        self.messageTypes = {
            'all': self.processAll,
            'list': self.processList,
            'new': self.processNew,
            'send': self.processSend,
            'recv': self.processRecv,
            'create': self.processCreate,
            'receipt': self.processReceipt,
            'status': self.processStatus,
            
            'session': self.processSession, 
        }

        self.registry = ServerRegistry()

    def handleRequest(self, s, request, client):
        """Handle a request from a client socket.
        """
        try:
            logging.info("HANDLING message from %s: %r" %
                         (client, repr(request)))

            try:
                req = json.loads(request)
            except:
                logging.exception("Invalid message from client")
                return

            if not isinstance(req, dict):
                log(logging.ERROR, "Invalid message format from client")
                return

            if 'type' not in req:
                ok,client.blockChain, req = ourCrypto.verify_integrity(req, client.sessionKeys, client.blockChain)

                if ok is not True:
                    payload = {"error": "No integrity in package or package malformed", "last_hash": sendBytes(client.blockChain.currentHash)}
                    payload, client.blockChain = ourCrypto.generate_integrity(payload, client.sessionKeys, client.blockChain)
                    client.sendResult( payload )
                    return


                req = req["payload"]

                if 'type' not in req:
                    log(logging.ERROR, "Message has no TYPE field")
                    return

            if req['type'] in self.messageTypes:
                self.messageTypes[req['type']](req, client)
            else:
                log(logging.ERROR, "Invalid message type: " +
                    str(req['type']) + " Should be one of: " + str(self.messageTypes.keys()))
                client.sendResult({"error": "unknown request"})

        except Exception as e:
            logging.exception("Could not handle request")

    def processCreate(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))


        signature = recvBytes(data["signature"])


        del data["signature"]
        del data["type"]

        try:

            client.clientCertificate = Certificate(recvBytes(data["cert"]))
            valido = client.clientCertificate.validate_signature(json.dumps(data, sort_keys =True), signature)
            print(valido)
        except Exception as e:
            raise e


        data["signature"] = sendBytes(signature)

        data_error = ""
        if 'uuid' not in data.keys():
            print("no data.keys")
            log(logging.ERROR, "No \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            data_error = {"error": "wrong message format"}

        uuid = data['uuid']
        if not isinstance(uuid, int): # is it an error ?
            log(logging.ERROR, "No valid \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            data_error = {"error": "wrong message format"}
            
        #esta a usar a userExists para verificar o uuid e o id
        if self.registry.userExistsUuid(uuid):
            #do lado do servidor agora os clientes tem uuid e id associados
            client.id, client.uuid = self.registry.userExistsUuid(uuid)

            # Comparing certificates just to be sure :)
            cert_stored  = recvBytes(self.registry.listUsers(client.id)[0]['cert'])
            cert_recived = recvBytes(data["cert"])

            if cert_stored == cert_recived:
                data_error = {"login": "Just signed in", "result": client.id}
            else:
                data_error = {"error": "You are not who you say you are :) Get Rekt m8"}


        if data_error:
            data_error = load_payload(data_error)
            payload, client.blockChain = ourCrypto.generate_integrity(data_error, client.sessionKeys, client.blockChain)
            client.sendResult( payload )
            return


        me = self.registry.addUser(data)

        client.id = me.id
        client.uuid = uuid

        payload = {"result": me.id}
        payload = load_payload(payload)
        payload, client.blockChain = ourCrypto.generate_integrity(payload, client.sessionKeys, client.blockChain)
        client.sendResult( payload )

    def processList(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))
        data = unload_payload(data)
        user = 0  # 0 means all users
        userStr = "all users"
        if 'id' in data.keys():
            user = int(data['id'])
            userStr = "user%d" % user

        log(logging.DEBUG, "List %s" % userStr)

        userList = self.registry.listUsers(user)
        if userList == None:
            log(logging.ERROR, "User does not exist: " + json.dumps(data))
            data_error = {"error": "user does not exist"}
            data_error = load_payload(data_error)
            payload, client.blockChain = ourCrypto.generate_integrity(data_error, client.sessionKeys, client.blockChain)
            client.sendResult( payload )
            return


        payload = load_payload({"result": userList})
        payload, client.blockChain = ourCrypto.generate_integrity(payload, client.sessionKeys, client.blockChain)
        client.sendResult(payload)

    def processNew(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))
        data_error = ""

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            data_error = {"error": "wrong message format"}

        if client.id != data["id"]:
            log(logging.ERROR,
                "No valid \"id\" field in \"all\" message, (not your mail box): " + json.dumps(data))
            data_error = {"error": "Not your mail box"}

        if data_error:
            data_error = load_payload(data_error)
            payload, client.blockChain = ourCrypto.generate_integrity(data_error, client.sessionKeys, client.blockChain)
            client.sendResult( payload )
            return
        
        payload = {"result": self.registry.userNewMessages(user)}
        payload = load_payload(payload)
        payload, client.blockChain = ourCrypto.generate_integrity(payload, client.sessionKeys, client.blockChain)
        client.sendResult(payload)

    def processAll(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))
        data_error = ""

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            data_error = {"error": "wrong message format"}
            # removi return's aqui e no if abaixo para garantir que não retorna. Só deve retornar no if data_error
        
        if client.id != data["id"]:
            log(logging.ERROR,
                "No valid \"id\" field in \"all\" message, (not your mail box): " + json.dumps(data))
            data_error = {"error": "Not your mail box"}

        if data_error:
            data_error = load_payload(data_error)
            payload, client.blockChain = ourCrypto.generate_integrity(data_error, client.sessionKeys, client.blockChain)
            client.sendResult( payload )
            return
        
        payload = {"result": [self.registry.userAllMessages(user), self.registry.userSentMessages(user)]}
        payload = load_payload(payload)

        payload, client.blockChain = ourCrypto.generate_integrity(payload, client.sessionKeys, client.blockChain)
        client.sendResult(payload)

    def processSend(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))
        data_error = ""

        if not set(data.keys()).issuperset(set({'src', 'dst', 'msg', 'copy'})):
            log(logging.ERROR,
                "Badly formated \"send\" message: " + json.dumps(data))
            data_error = load_payload({"error": "wrong message format"})
            payload, client.blockChain = ourCrypto.generate_integrity(data_error, client.sessionKeys, client.blockChain)
            client.sendResult( payload )
            return

        srcId = int(data['src'])
        dstId = int(data['dst'])
        msg = str("\n".join([data['msg']['text'], data['msg']['signature']]))
        copy = str("\n".join([data['copy']['copy'], data['copy']['signature']]))

        if not self.registry.userExists(srcId):
            log(logging.ERROR,
                "Unknown source id for \"send\" message: " + json.dumps(data))
            data_error = {"error": "wrong parameters"}

        if not self.registry.userExists(dstId):
            log(logging.ERROR,
                "Unknown destination id for \"send\" message: " + json.dumps(data))
            data_error = {"error": "wrong parameters"}

        if client.id != srcId or srcId == None:
            log(logging.ERROR,
                "No valid \"src id\" field in \"send\" message, (not your mail box): " + json.dumps(data))
            data_error = {"error": "Cant send msg from other person, user your source ID"}

        if data_error:
            data_error = load_payload(data_error)
            payload, client.blockChain = ourCrypto.generate_integrity(data_error, client.sessionKeys, client.blockChain)
            client.sendResult( payload )
            return

        # Save message and copy
        payload = {"result": self.registry.sendMessage(srcId, dstId, msg, copy)}
        payload = load_payload(payload)
        payload, client.blockChain = ourCrypto.generate_integrity(payload, client.sessionKeys, client.blockChain)
        client.sendResult(payload)

    def processRecv(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        data_error = ""
        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"recv\" message: " +
                json.dumps(data))
            data_error = {"error": "wrong parameters"}
            payload, client.blockChain = ourCrypto.generate_integrity(data_error, client.sessionKeys, client.blockChain)
            client.sendResult( payload )
            return

        fromId = int(data['id'])
        msg = recvBytes(data['msg']).decode('utf-8')
        if not self.registry.userExists(fromId):
            log(logging.ERROR,
                "Unknown source id for \"recv\" message: " + json.dumps(data))
            data_error = {"error": "wrong parameters"}

        if client.id != fromId:
            log(logging.ERROR,
                "No valid \"id\" field in \"recv\" message, (not your mail box): " + json.dumps(data))
            data_error = {"error": "Not your mail box"}

        if not self.registry.messageExists(fromId, msg):
            log(logging.ERROR,
                "Unknown mail box for \"recv\" message: " + json.dumps(data))
            data_error = {"error": "wrong parameters"}

        if data_error:
            data_error = load_payload(data_error)
            payload, client.blockChain = ourCrypto.generate_integrity(data_error, client.sessionKeys, client.blockChain)
            client.sendResult( payload )
            return

        # Read message

        response = self.registry.recvMessage(fromId, msg)

        payload = {"payload": response}
        payload = load_payload(payload)
        payload, client.blockChain = ourCrypto.generate_integrity(payload, client.sessionKeys, client.blockChain)
        client.sendResult(payload)

    def processReceipt(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))
        data_error = {}

        fromId = int(data['id'])
        if client.id != fromId:
            log(logging.ERROR,
                "No valid \"id\" field in \"recv\" message, (not your mail box): " + json.dumps(data))
            data_error = {"error": "Not your mail box"}

        if not set({'id', 'msg', 'receipt'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"receipt\" message: " +
                json.dumps(data))
            data_error = {"error": "wrong request format"}

        if data_error:
            data_error = load_payload(data_error)
            payload, client.blockChain = ourCrypto.generate_integrity(data_error, client.sessionKeys, client.blockChain)
            client.sendResult( payload )
            return

        fromId = int(data["id"])
        msg = get_bytes(base64.b64decode(data['msg']))
        receipt = str(data['receipt'])

        if not self.registry.messageWasRed(str(fromId), msg):
            log(logging.ERROR, "Unknown, or not yet red, message for \"receipt\" request " + json.dumps(data))
            data_error = {"error": "wrong parameters"}

        if data_error:
            data_error = load_payload(data_error)
            payload, client.blockChain = ourCrypto.generate_integrity(data_error, client.sessionKeys, client.blockChain)
            client.sendResult( payload )
            return

        self.registry.storeReceipt(fromId, msg, receipt)

    def processStatus(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))
        data_error = {}

        fromId = int(data['id'])
        if client.id != fromId:
            log(logging.ERROR,
                "No valid \"id\" field in \"recv\" message, (not your mail box): " + json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"receipt\" message: " +
                json.dumps(data))
            data_error = {"error": "wrong request format"}

        fromId = int(data['id'])
        msg = str(data["msg"])

        if(not self.registry.copyExists(fromId, msg)):
            log(logging.ERROR, "Unknown message for \"status\" request: " + json.dumps(data))
            data_error = {"error": "wrong parameters"}

        if data_error:
            data_error = load_payload(data_error)
            payload, client.blockChain = ourCrypto.generate_integrity(data_error, client.sessionKeys, client.blockChain)
            client.sendResult( payload )
            return

        response = self.registry.getReceipts(fromId, msg)

        payload = {"payload": response}

        payload = load_payload(payload)
        payload, client.blockChain = ourCrypto.generate_integrity(payload, client.sessionKeys, client.blockChain)
        client.sendResult(payload)

    def processSession(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'type', 'payload', 'signed', 'cert'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong session message format"})
        #verificar payload e assinatura

        if data["payload"]["status"] == 1:
            try:
                client.clientCertificate = Certificate(ourCrypto.recvBytes(data["cert"]))
                valido = client.clientCertificate.validate_signature(json.dumps(data["payload"], sort_keys =True), ourCrypto.recvBytes(data["signed"]))

            except Exception as e:
                print(e)
                payload = {"error" : "Client invalid certificate", "randomID" :data["payload"]["randomID"]}
                client.sendResult(client.certServe.generate(payload))
                return
            payload = {"pubKey" : ourCrypto.sendPubKey(client.sessionKeys.pubKey), "status" : 2, "randomID" :data["payload"]["randomID"]}
            client.sendResult(client.certServe.generate(payload))
            return

        #se tiver valida
        if data["payload"]["status"] == 2:
            try:
                client.clientCertificate = Certificate(ourCrypto.recvBytes(data["cert"]))
                valido = client.clientCertificate.validate_signature(json.dumps(data["payload"], sort_keys =True), ourCrypto.recvBytes(data["signed"]))
            except Exception as e:
                payload = {"error" : "Invalida certificate"}
                client.sendResult(client.certServe.generate(payload))
                return

            peer_pub_key = data["payload"]["pubKey"]

            client.sessionKeys.getSecret(ourCrypto.recvPubKey(peer_pub_key))

            
            salt = ourCrypto.recvBytes(data["payload"]["salt"])
            key, salt = client.sessionKeys.deriveShared(salt)
            hashS = ourCrypto.recvBytes(data["payload"]["hash"])
            del data["payload"]["hash"]
            serverHash = ourCrypto.generate_hash(0,'0', json.dumps(data["payload"], sort_keys = True),key)

            if serverHash ==  hashS:
                client.blockChain = Block(0, '0', data["payload"], hashS)
                payload = {"ack" : "yes"}

                key, salt = client.sessionKeys.deriveShared()
                payload["salt"] = ourCrypto.sendBytes(salt)

                client.blockChain.generateNextBlock(json.dumps(payload,sort_keys = True), key)

                payload["hash"] = ourCrypto.sendBytes(client.blockChain.currentHash) 
                client.sendResult({"result": payload})
                return
            else:
                log(logging.ERROR, "Badly hash " +
                    json.dumps(data))
                payload = {"error": "wrong hash payload"}
                client.sendResult(client.certServe.generate(payload))
                return

