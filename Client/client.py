#!/usr/bin/env python
# -*- coding: utf-8 -*-

from socket import *
from log import *
import json
import os
from os import path
import sys
import base64

from random import randint
#---------------------------------------------- 
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

sys.path.append(path.join(path.dirname(path.realpath(__file__)),'../modules/'))
from cc_interection import CC_Interaction
from asymmetric import Asy_Cyphers 
from symmetric import Sym_Cyphers 
from DiffieHellman import DiffieHellman
from BlockChain import Block 
from asymmetric import derivateKey
import ourCrypto


ENCODING = 'utf-8'
TERMINATOR = "\r\n"
BUFSIZE = 512 * 1024

def get_int(question):
    try:
        return int(input(question))
    except:
        return None

def randomMsgId():
    return int.from_bytes(os.urandom(16), byteorder="big")

class Client(object):
    """docstring for Client"""
    def __init__(self):
        super(Client, self).__init__()

        # Server connection variables
        try:
            self.server_ip = "127.0.0.1"
            self.server_port = 8080
            self.socket = socket(AF_INET, SOCK_STREAM)
            self.socket.connect((self.server_ip, self.server_port))
        except Exception as e:
            log_error("Error connecting with the server")
            raise
            return
        self.listMsgID = []
        self.cc = CC_Interaction()
        try:
            self.uuid = self.cc.get_pubkey_hash_int() 
        except ValueError:
            log_error("Error getting uuid")
            raise
            return
        self.id = None 
        self.sessionKeys = DiffieHellman()

        #assimetrica gerada por nos (nao do cc)
        self.AsyCypher = Asy_Cyphers(self.uuid)
        self.blockChain = None

        #if not self.id:
        #    log_info("Creating message box...")
        #    self.Create()

        




    def get_self_ID(self):
        """
            Returns message box ID for the client UUID
            Returns None if it doesn't exist
        """
        
        msgID = randomMsgId() 
        #falta a parte de assinar este msgID
        self.listMsgID.append(msgID)

        message = {'type' : 'list',
                   'randomId' : msgID}
        self.send_to_server(message)
        response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))

        if response.get('randomId') not in self.listMsgID:
            print(msgID)
            print(response.get('randomId'))
            log_error("This randomId is not mine")

        if not response.get('error'):
            for x in response.get('result'):
                if self.uuid == int(x.get('description').get('uuid')):
                    log_info("You have a message box already registered (ID: %s)" % x.get('id'))
                    return int(x.get('id'))


        log_info("You don't have a message box yet.")
        return None



    def send_to_server(self, message):
        self.socket.sendall((json.dumps(message) +TERMINATOR).encode('utf-8'))

    #temos de assinar os conteudos, verificar a resposta se vem assinada pelo servidor
    #estou a verificar o randomId mas nao é a melhor maneira
    #o que se pode fazer e quando se gera um novo random ID ele vir ja assinado
    def Create(self):
        msgID = randomMsgId() 
        #falta a parte de assinal este msgID
        self.listMsgID.append(msgID)
        message = { 'type' : 'create',
                    'uuid' : self.uuid,
                    'publicKey' : self.AsyCypher.getPub().decode(ENCODING),
                    'cert' : self.cc.getCertPem().decode(ENCODING),
                    'randomId': msgID
                  }
        print(message)
        self.send_to_server(message)
        response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))
        #verificar o msgID se esta na lista de enviados? e verificar assinatura
        print(response)
        
        if response.get('randomId') not in self.listMsgID:
            print(msgID)
            print(response.get('randomId'))
            log_error("This randomId is not mine")

        if response.get('error'):
            log_error("This uuid already has a message box")

        else:
            self.id = response.get('result')
            log_success("Message box with created successfully (ID: %s)" % str(response.get('result')))


    def List(self, uid = None):
        msgID = randomMsgId() 
        #falta a parte de assinal este msgID
        self.listMsgID.append(msgID) 
        if uid == None:
            message = {'type' : 'list', 'randomId' : msgID}
        else:
            message = {'type' : 'list', 'id' : uid, 'randomId' : msgID}

        self.send_to_server(message)
        response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))

        if response.get('error'):
            log_error(response.get('error'))
        else:
            try:
                for x in response.get('result'):
                    print(x)
            except Exception as e:
                log_info("Id does not exist")


    def New(self, user_id):
        message = { 'type' : 'new', 
                    'id' : user_id
                  }
        
        self.send_to_server(message)
        response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))

        if response.get('error'):
            log_error(response.get('error'))

        elif len(response.get('result')) == 0:
            log_info("No new messages to show")

        else:
            for x in response.get('result'):
                print(x)


    def All(self, uid):
        message = {'type' : 'all', 'id' : uid}
        self.send_to_server(message)
        response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))
        if response.get('error'):
            log_error(response.get('error'))
        else:
            print(response)

    def Send(self, dst, msg, src = None):
        src = self.id if src == None else src
        print("encode")
        print(bytes(msg,'utf-8'))
        txtEnc = self.AsyCypher.cyph(bytes(msg, 'utf-8'))
        message = { 'type'	: 'send', 
                    'src'	: src,
                    'dst'	: dst,
                    'msg'	: txtEnc.decode(ENCODING),
                    'copy'	: txtEnc.decode(ENCODING),
                  }

        self.send_to_server(message)
        response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))
        print(response)


    def Recv(self, receiver, box):
        message = { 'type'	: 'recv', 
                    'id'	: receiver,  
                    'msg'	: box,
                  }

        self.send_to_server(message)
        response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))
        if response.get('error'):
            log_error(response.get('error'))
        else:
            txtEnc = response.get('result')[1].encode(ENCODING)
            txtDenc = self.AsyCypher.decyph(txtEnc)
            print(txtDenc)
            print(txtDenc.decode('utf-8'))
                

    def Receipt(self, box):
        message = { 'type'		: 'receipt', 
                    'id'		: self.id,  
                    'msg'		: box,
                    'receipt'	: "Vamos imaginar que este texto e uma assinatura"  # hint: Não é ;) 
                  }

        self.send_to_server(message)
        self.socket.settimeout(0.5)
        try:
            response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))
            log_error(response.get('error'))
        except:
            log_success("Sent")
        self.socket.settimeout(None)


    def Status(self, sender, box):
        message = { 'type'	: 'status', 
                    'id'	: sender,  
                    'msg'	: box,
                  }

        self.send_to_server(message)
        response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))
        if response.get('error'):
            log_error(response.get('error'))
        else:
            print(response)
        pass



def menu():
    print("\nChoose an option: ")
    print("1 - CREATE message box")
    print("2 - LIST message boxes")
    print("3 - List NEW messages in message box")
    print("4 - List ALL messages in message box")
    print("5 - SEND a message to a message box")
    print("6 - RECEIV a specific message from a message box")
    print("7 - Send a message RECEIPT")
    print("8 - Check for message reception STATUS")
    print("0 - EXIT")


if __name__ == "__main__":

    try:
        client = Client()
        msg = {"status" : 1, "randomID" : randomMsgId()}
        message = { 'type'	: 'session', 
                    'msg'	: msg,  
                    'signed'	: "assinatura da msg",
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
        #self.id = self.get_self_ID()
                
    except Exception as e:
        raise e

    while 1:
        menu()
        x = None
        try:
            x = int(input("Opt: "))
        except Exception as e:
            print("Must be an integer")


        if x == 1:
            client.Create()

        elif x == 2:
            uid = get_int(question = "User ID? ")
            client.List(uid)

        elif x == 3:
            result = get_int(question = "User ID? ")
            client.New(result) if result else log_error("Invalid Value")

        elif x == 4:
            result = get_int(question = "User ID? ")
            client.All(result) if result else log_error("Invalid Value")

        elif x == 5:  # Send Function

            dst = get_int(question = "Destination User ID? ")

            msg = str(input("Message? "))

            if dst == None:
                log_error("Invalid Destination ID")

            if msg == None:
                log_error("Invalid Message")
            if dst == None or msg == None:
                continue
            else:
                client.Send(dst, msg)


        elif x == 6:
            receiver = get_int(question = "Receiver User ID? ")
            if receiver == None:
                log_error("Invalid Value")

            sender = get_int(question = "Sender User ID? ")
            if sender == None:
                log_error("Invalid Value")

            boxId = get_int(question = "Message ID? ")
            if boxId == None:
                log_error("Invalid Value")

            box = str(sender) + "_" + str(boxId)
            client.Recv(receiver, box)


        elif x == 7:
            sender = get_int(question = "Sender User ID? ")
            if sender == None:
                log_error("Invalid Value")

            boxId = get_int(question = "Message ID? ")
            if boxId == None:
                log_error("Invalid Value")


            box = str(sender) + "_" + str(boxId)
            client.Receipt(box)

        elif x == 8:
            sender = get_int(question = "Sender User ID? ")
            if sender == None:
                log_error("Invalid Value")

            receiver = get_int(question = "Receiver User ID? ")
            if receiver == None:
                log_error("Invalid Value")

            boxId = get_int(question = "Message ID? ")
            if boxId == None:
                log_error("Invalid Value")

            box = str(receiver) + "_" + str(boxId)
            client.Status(sender, box)

        elif x == 0:
            break

        else:
            continue



    client.socket.close()
    print("byee :) ")


