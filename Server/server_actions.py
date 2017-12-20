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
import ourCrypto

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

        if 'uuid' not in data.keys():
            print("no data.keys")
            log(logging.ERROR, "No \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        uuid = data['uuid']
        if not isinstance(uuid, int): # is it an error ?
            log(logging.ERROR, "No valid \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return
        #esta a usar a userExists para verificar o uuid e o id
        if self.registry.userExistsUuid(uuid):
            log(logging.ERROR, "User already exists: " + json.dumps(data))
            client.sendResult({"error": "uuid already exists"})
            return

        me, responseID = self.registry.addUser(data)
        client.sendResult({"result": me.id, "randomId" : responseID})

    def processList(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = 0  # 0 means all users
        userStr = "all users"
        if 'id' in data.keys():
            user = int(data['id'])
            userStr = "user%d" % user

        if 'randomId' not in data.keys():
            log(logging.ERROR, "No random id" + json.dumps(data))
            client.sendResult({"error": "No random id"})


        log(logging.DEBUG, "List %s" % userStr)

        responseID = data['randomId']
        userList = self.registry.listUsers(user)

        client.sendResult({"result": userList, "randomId" : responseID})

    def processNew(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        client.sendResult(
            {"result": self.registry.userNewMessages(user)})

    def processAll(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        client.sendResult({"result": [self.registry.userAllMessages(user), self.registry.userSentMessages(user)]})

    def processSend(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set(data.keys()).issuperset(set({'src', 'dst', 'msg', 'msg'})):
            log(logging.ERROR,
                "Badly formated \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})

        srcId = int(data['src'])
        dstId = int(data['dst'])
        msg = str(data['msg'])
        copy = str(data['copy'])

        if not self.registry.userExists(srcId):
            log(logging.ERROR,
                "Unknown source id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        if not self.registry.userExists(dstId):
            log(logging.ERROR,
                "Unknown destination id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        # Save message and copy

        response = self.registry.sendMessage(srcId, dstId, msg, copy)

        client.sendResult({"result": response})

    def processRecv(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"recv\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})

        fromId = int(data['id'])
        msg = str(data['msg'])

        if not self.registry.userExists(fromId):
            log(logging.ERROR,
                "Unknown source id for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        if not self.registry.messageExists(fromId, msg):
            log(logging.ERROR,
                "Unknown source msg for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        # Read message

        response = self.registry.recvMessage(fromId, msg)

        client.sendResult({"result": response})

    def processReceipt(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg', 'receipt'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"receipt\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong request format"})

        fromId = int(data["id"])
        msg = str(data['msg'])
        receipt = str(data['receipt'])

        if not self.registry.messageWasRed(str(fromId), msg):
            log(logging.ERROR, "Unknown, or not yet red, message for \"receipt\" request " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        self.registry.storeReceipt(fromId, msg, receipt)

    def processStatus(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})

        fromId = int(data['id'])
        msg = str(data["msg"])

        if(not self.registry.copyExists(fromId, msg)):
            log(logging.ERROR, "Unknown message for \"status\" request: " + json.dumps(data))
            client.sendResult({"error", "wrong parameters"})
            return

        response = self.registry.getReceipts(fromId, msg)
        client.sendResult({"result": response})

    def processSession(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'type', 'msg', 'signed', 'cert'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong session message format"})
        #verificar msg e assinatura

        if data["msg"]["status"] == 1:


            msg = {"pubKey" : ourCrypto.sendPubKey(client.sessionKeys.pubKey), "status" : 2, "randomID" :data["msg"]["randomID"]}
            #sign = sign(msg)
            sign = "teste"
            client.sendResult({"result": msg, "signed" : sign})
            return

        #se tiver valida
        if data["msg"]["status"] == 2:
            peer_pub_key = data["msg"]["pubKey"]

            client.sessionKeys.getSecret(ourCrypto.recvPubKey(peer_pub_key))

            
            salt = ourCrypto.recvBytes(data["msg"]["salt"])
            key, salt = client.sessionKeys.deriveShared(salt)
            serverHash = ourCrypto.verifyHash(0,'0', json.dumps(data["msg"], sort_keys = True),key)

            if serverHash ==  ourCrypto.recvBytes(data["hash"]):
                client.blockChain = Block(0, '0', data["msg"], data["hash"])
                msg = {"ack" : "yes"}
                client.blockChain.generateNextBlock(msg, client.sessionKeys.sharedKey)
                msg["hash"] = ourCrypto.sendBytes(client.blockChain.currentHash) 
                client.sendResult({"result": msg})
                return
            else:
                log(logging.ERROR, "Badly hash " +
                    json.dumps(data))
                client.sendResult({"error": "wrong hash msg"})
                return

