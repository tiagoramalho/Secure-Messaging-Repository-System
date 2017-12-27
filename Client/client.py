#!/usr/bin/env python
# -*- coding: utf-8 -*-

from socket import *
from log import *
import json
import os
from os import path
import sys
import base64

from datetime import date
#---------------------------------------------- 
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

sys.path.append(path.join(path.dirname(path.realpath(__file__)),'../modules/'))
from cc_interection import CC_Interaction
from cc_interection import Certificate
from asymmetric import Asy_Cyphers 
from symmetric import Sym_Cyphers 
from DiffieHellman import DiffieHellman
from BlockChain import Block 
from asymmetric import derivateKey
import ourCrypto
from ourCrypto import sendBytes
from ourCrypto import recvBytes
from ourCrypto import load_payload
from ourCrypto import unload_payload
from ourCrypto import get_bytes

from pprint import pprint

import sessionConnect


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
            log_error("Error connecting with the server\n")
            raise
            return
        self.cc = CC_Interaction()
        try:
            self.uuid = self.cc.get_pubkey_hash_int() 
        except ValueError:
            log_error("Error getting uuid\n")
            raise
            return
        self.id = None 
        self.sessionKeys = DiffieHellman()

        #assimetrica gerada por nos (nao do cc)

        self.AsyCypher = Asy_Cyphers(self.uuid)
        self.blockChain = None
        self.certCertificate = None


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
        payload = { 'uuid' : self.uuid,
                    'publicKey' : self.AsyCypher.getPub(),
                    'cert' : self.cc.cert.dump_certificate(),
                    'subject_name' : self.cc.cert.get_subject(),
                    #'randomId': msgID
                  }
        
        payload = load_payload(payload)

        signature = self.cc.sign(json.dumps(payload, sort_keys = True))

        payload["signature"] = sendBytes(signature)
        payload["type"] = "create"
            
        payload, self.blockChain = ourCrypto.generate_integrity(payload, self.sessionKeys, self.blockChain)
        self.send_to_server(payload)

        response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))

        ok, self.blockChain, response = ourCrypto.verify_integrity(response, self.sessionKeys, self.blockChain)
        if not ok:
            print("No integrity of message. Exiting...")
            sys.exit(-1)
        #verificar o msgID se esta na lista de enviados? e verificar assinatura
        response = response["payload"]
        response = unload_payload(response)
        if response.get('error'):
            log_error(response.get('error').decode(ENCODING))

        elif response.get('login'):
            self.id = response.get('result')
            log_info(response.get('login').decode(ENCODING))

        else:
            self.id = response.get('result')
            log_success("Message box with created successfully (ID: %s)" % str(response.get('result')))


    def List(self, uid = None, get_response = False):
        #falta a parte de assinal este msgID

        payload = {}

        if uid == None:
            payload = {'type' : 'list'}
        else:
            payload = {'type' : 'list', 'id' : uid}


        payload = load_payload(payload)

        payload, self.blockChain = ourCrypto.generate_integrity(payload, self.sessionKeys, self.blockChain)
        self.send_to_server(payload)

        response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))
        ok, self.blockChain, response = ourCrypto.verify_integrity(response, self.sessionKeys, self.blockChain)
        if not ok:
            print("No integrity of message. Exiting...")
            sys.exit(-1)
        #verificar o msgID se esta na lista de enviados? e verificar assinatura

        response = response["payload"]


        if response.get('error'):
            response = get_bytes(unload_payload(response))
            log_error(response.get('error'))    
            return
        else:
            response = response["result"]
            response = unload_payload(response)
            if get_response:
                return response
            try:
                print("-----------\n USER LIST \n-----------")
                for x in response:
                    if x.get("description") !=None:
                        print("\nID: {0}\nName: {1}\nUUID: {2}\n-----------".format(
                            x.get("id"),
                            get_bytes(x.get("description").get("subject_name")),
                            x.get("description").get("uuid")

                            )
                        )
                    else:
                        print("\nID: {0}\nName: {1}\nUUID: {2}\n-----------".format(
                            uid,
                            get_bytes(x.get("subject_name")),
                            x.get("uuid")

                            )
                        )
            except Exception as e:
                raise e
                log_info("Id does not exist")


    def New(self, uid):
        payload = { 'type' : 'new', 'id' : uid }
        payload = load_payload(payload)

        payload, self.blockChain = ourCrypto.generate_integrity(payload, self.sessionKeys, self.blockChain)
        self.send_to_server(payload)

        response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))
        ok, self.blockChain, response= ourCrypto.verify_integrity(response, self.sessionKeys, self.blockChain)
        if not ok:
            print("No integrity of message. Exiting...")
            sys.exit(-1)
        response = response["payload"]
        response = unload_payload(response)

        if response.get('error'):
            log_error(response.get('error').decode(ENCODING))

        elif len(response.get('result')) == 0:
            log_info("No new messages to show")

        else:
            log_success("New messages: ")
            for x in response.get('result'):
                print("\tmessage: " +  x.decode(ENCODING))

    def All(self, uid):
        payload = {'type' : 'all', 'id' : uid}
        payload = load_payload(payload)

        payload, self.blockChain = ourCrypto.generate_integrity(payload, self.sessionKeys, self.blockChain)
        self.send_to_server(payload)

        response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))

        ok, self.blockChain, response = ourCrypto.verify_integrity(response, self.sessionKeys, self.blockChain)
        if not ok:
            print("No integrity of message. Exiting...")
            sys.exit(-1)
        #verificar o msgID se esta na lista de enviados? e verificar assinatura
        response = response["payload"]
        response = unload_payload(response)
        
        if response.get('error'):
            log_error(response.get('error').decode(ENCODING))

        else:
            received = ""
            for x in response.get('result')[0]:
                received += x.decode(ENCODING) + "; " 
            log_success("Received Message: %s" % str(received if received != "" else "No received messages"))
            sended = ""

            for x in response.get('result')[1]:
                sended += x.decode(ENCODING) + "; " 
            log_success("Sended Message: %s" % str(sended if sended != "" else "No sended messages"))

    def Send(self, dst, msg):

        if self.id == None:
            log_error("No user id, pls create/login a user")
            return
        list_result = self.List(dst, get_response = True)
        if list_result == None:
            log_error("No destination user ID")
            return
        list_result = list_result[0]
        signature = recvBytes(list_result["signature"].decode(ENCODING))
        del list_result["signature"]
        valido = False
        try:
            self.certCertificate = Certificate(recvBytes(list_result["cert"].decode(ENCODING)))
            list_result["cert"] = list_result["cert"].decode(ENCODING)
            list_result["publicKey"] = list_result["publicKey"].decode(ENCODING)
            list_result["subject_name"] = list_result["subject_name"].decode(ENCODING)
            log_info("Validating public key of the recipient")
            valido = self.certCertificate.validate_signature(json.dumps(list_result, sort_keys =True), signature)
        except Exception as e:
            pass

        if not valido:
            log_error("Information in the description is not reliable")
            return
        list_result = get_bytes(self.List(dst, get_response = True))[0]

        signature = self.cc.sign(msg)

        text = self.AsyCypher.cyph(bytes(msg, 'utf-8'), public_key = list_result["publicKey"])
        copy = self.AsyCypher.cyph(bytes(msg, 'utf-8'))

        payload = { 'type'	: 'send', 
                    'src'	: self.id,
                    'dst'	: dst,
                    'msg'	: {"text" : text, "signature" : signature},
                    'copy'	: {"copy" : copy,  "signature" : signature},
                  }

        payload = load_payload(payload)
        payload, self.blockChain = ourCrypto.generate_integrity(payload, self.sessionKeys, self.blockChain)

        self.send_to_server(payload)

        response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))

        ok, self.blockChain, response = ourCrypto.verify_integrity(response, self.sessionKeys, self.blockChain)
        if not ok:
            print("No integrity of message. Exiting...")
            sys.exit(-1)
        #verificar o msgID se esta na lista de enviados? e verificar assinatura
        response = response["payload"]
        response = unload_payload(response)
        
        if response.get('error'):
            log_error(response.get('error').decode(ENCODING))
        else:
            log_success("Message identifier: %s; Receipt identifier %s" % (str(response["result"][0].decode(ENCODING)), str(response["result"][1].decode(ENCODING))))


    def Recv(self, box):
        if self.id == None:
            log_error("No user id, pls create/login a user\n")
            return
        payload= { 'type'	: 'recv', 
                    'id'	: self.id,  
                    'msg'	: str(box),
                  }

        payload = load_payload(payload)
        payload, self.blockChain = ourCrypto.generate_integrity(payload, self.sessionKeys, self.blockChain)

        self.send_to_server(payload)
        response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))
        ok, self.blockChain, response = ourCrypto.verify_integrity(response, self.sessionKeys, self.blockChain)
        if not ok:
            print("No integrity of message. Exiting...")
            sys.exit(-1)

        response = response["payload"]
        response = unload_payload(response)
        
        if response.get('error'):
            log_error(response.get('error').decode(ENCODING))
        else:
            intermidiate_data = response["payload"][1].split(bytes("\n", "utf-8"))

            plaintext = self.AsyCypher.decyph(intermidiate_data[0])
            log_success("\nMessage: %s \n" %str(plaintext.decode(ENCODING)))

            self.Receipt(box, plaintext.decode(ENCODING))

                

    def Receipt(self, box, msg):
        if self.id == None:
            log_error("No user id, pls create a user\n")
            return

        log_info("Sending receipt for message number %s " % str(box))

        signature = self.cc.sign(msg)

        payload = { 'type'		: 'receipt', 
                    'id'		: self.id,  
                    'msg'		: str(box),
                    'receipt'	: signature  # hint: Não é ;) 
                  }

        payload = load_payload(payload)
        payload, self.blockChain = ourCrypto.generate_integrity(payload, self.sessionKeys, self.blockChain)
        self.send_to_server(payload)


        self.socket.settimeout(2)

        try:
            response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))
            ok, self.blockChain, response = ourCrypto.verify_integrity(response, self.sessionKeys, self.blockChain)

            if not ok:
                print("No integrity of message. Exiting...")
                sys.exit(-1)
            response = response["payload"]
            response = get_bytes(unload_payload(response))
            log_error(response.get('error'))

        except Exception as e:
            log_success("Receipt was sent\n")

        self.socket.settimeout(None)


    def Status(self, box):
        if self.id == None:
            log_error("No user id, pls create a user\n")
            return
        message = { 'type'	: 'status', 
                    'id'	: self.id,  
                    'msg'	: box,
                  }

        self.send_to_server(message)
        response = json.loads(self.socket.recv(BUFSIZE).decode('utf-8'))
        ok, self.blockChain, response = ourCrypto.verify_integrity(response, self.sessionKeys, self.blockChain)
        if not ok:
            print("No integrity of message. Exiting...")
            sys.exit(-1)

        response = response["payload"]
        response = unload_payload(response)
         
        valido = False
        if response.get('error'):
            log_error(response.get('error').decode(ENCODING))
        else:

            response = response["payload"]
            msg = response["msg"]
            receipt = response["receipts"]
            
            receiptID = ""
            valido = False
            validoCert = False
            for x in receipt:
                if receiptID != x["id"]:
                    receiptID = x["id"]
                    list_result = (self.List(receiptID, get_response = True)[0])

                    signature = recvBytes(list_result["signature"].decode(ENCODING))
                    del list_result["signature"]
                    try:
                        self.certCertificate = Certificate(recvBytes(list_result["cert"].decode(ENCODING)))
                        list_result["cert"] = list_result["cert"].decode(ENCODING)
                        list_result["publicKey"] = list_result["publicKey"].decode(ENCODING)
                        list_result["subject_name"] = list_result["subject_name"].decode(ENCODING)
                        log_info("Validating certificate\n")
                        validoCert = self.certCertificate.validate_signature(json.dumps(list_result, sort_keys =True), signature)
                    except Exception as e:
                        pass
                if validoCert:
                    intermidiate_data = msg.split(bytes("\n", "utf-8"))

                    plaintext = self.AsyCypher.decyph(intermidiate_data[0])
                    try:
                        signature = recvBytes(x["receipt"].decode(ENCODING))
                        plaintext = plaintext.decode(ENCODING)
                        log_info("Validating receipt\n")
                        valido = self.certCertificate.validate_signature(plaintext, signature)
                    except Exception as e:
                        pass

                    if valido:
                        valido = False
                        log_success("Authenticated receipt. ID-%s Date-%s \n" % (str(x["id"].decode(ENCODING)), str(date.fromtimestamp(int(x["date"].decode(ENCODING))/1000))))
                    else:
                        log_error("Unauthenticated receipt. ID-%s Date-%s \n" % (str(x["id"].decode(ENCODING)), str(date.fromtimestamp(int(x["date"].decode(ENCODING))/1000))))
                else:
                    log_error("Information in the description is not reliable \n")

                




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
        ok = sessionConnect.sessionConnect(client)
                
    except Exception as e:
        raise e
    if ok:
        client.Create()
    else:
        sys.exit(-1)
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
            client.New(result) if result else log_error("Invalid Value\n")

        elif x == 4:
            result = get_int(question = "User ID? ")
            client.All(result) if result else log_error("Invalid Value\n")

        elif x == 5:  # Send Function

            dst = get_int(question = "Destination User ID? ")

            msg = str(input("Message? "))

            if dst == None:
                log_error("Invalid Destination ID\n")

            if msg == None:
                log_error("Invalid Message\n")
            if dst == None or msg == None:
                continue
            else:
                client.Send(dst, msg)


        elif x == 6:
            sender = get_int(question = "Sender User ID? ")
            if sender == None:
                log_error("Invalid Value\n")

            boxId = get_int(question = "Message ID? ")
            if boxId == None:
                log_error("Invalid Value\n")

            readed = get_int(question = "Has this message been read (1->Yes; 0->No):  ")
            if not readed:
                box = str("_".join([str(sender), str(boxId)]))
                client.Recv(box)
            else:
                box = str("_".join([str(sender), str(boxId)]))
                box = "_"+box
                client.Recv(box)

            


        elif x == 7:
            sender = get_int(question = "Sender User ID? ")
            if sender == None:
                log_error("Invalid Value\n")

            boxId = get_int(question = "Message ID? ")
            if boxId == None:
                log_error("Invalid Value\n")


            box = str(sender) + "_" + str(boxId)

            msg = str(input("Write the reading message? "))
            client.Receipt(box, msg)

        elif x == 8:
            sender = get_int(question = "Receiver User ID? ")
            if sender == None:
                log_error("Invalid Value\n")

            boxId = get_int(question = "Message ID? ")
            if boxId == None:
                log_error("Invalid Value\n")

            box = str(sender) + "_" + str(boxId)
            client.Status(box)

        elif x == 0:
            break

        else:
            continue



    client.socket.close()
    print("byee :) ")


