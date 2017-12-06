#!/usr/bin/env python
# -*- coding: utf-8 -*-

from socket import *
from log import *
import json
import os

import sys

from random import randint
#---------------------------------------------- 
import pkcs11
from pkcs11.util.rsa import encode_rsa_public_key, decode_rsa_public_key
from cryptography.hazmat.primitives.asymmetric import rsa
import getpass
import OpenSSL
from OpenSSL import crypto
from pkcs11 import Attribute, ObjectClass, Mechanism
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from pprint import pprint
#from aula_asym import *

TERMINATOR = "\r\n"

def get_int(question):
    try:
        return int(input(question))
    except:
        return None


def getPublicKeyCC():
    pem = None
    print("Getting token_label...")
    lib = pkcs11.lib("/usr/lib/opensc-pkcs11.so")
    token = lib.get_token(token_label="Auth PIN (CARTAO DE CIDADAO)")
    user_pin = ""
    if user_pin == "":
        user_pin = getpass.getpass("PIN ?")
    with token.open(user_pin = str(user_pin)) as session:
        pub = session.get_key(pkcs11.constants.ObjectClass.PUBLIC_KEY,
            pkcs11.KeyType.RSA, "CITIZEN AUTHENTICATION CERTIFICATE")
        pem = encode_rsa_public_key(pub)
    return pem 

class Client(object):
    """docstring for Client"""
    def __init__(self, uuid):
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

    
        try:
            self.uuid = int(uuid)
        except ValueError:
            log_error("UUID must be an integer")
            raise
            return

        self.id = self.get_self_ID()
        if not self.id:
            log_info("Creating message box...")
            self.Create()

        self.privShared = None #se poder usar o parameter como tenho posso ja por aqui
        self.pubShared = None
        self.sharedKey = None
        self.AsyCypher = None #modulo branco 
        




    def get_self_ID(self):
        """
            Returns message box ID for the client UUID
            Returns None if it doesn't exist
        """

        message = {'type' : 'list'}
        self.send_to_server(message)
        response = json.loads(self.socket.recv(1024).decode('utf-8'))

        if not response.get('error'):
            for x in response.get('result'):
                if self.uuid == int(x.get('description').get('uuid')):
                    log_info("You have a message box already registered (ID: %s)" % x.get('id'))
                    return int(x.get('id'))


        log_info("You don't have a message box yet.")
        return None



    def send_to_server(self, message):
        self.socket.sendall((json.dumps(message) +TERMINATOR).encode('utf-8'))

    def Create(self):

        message = { 'type' : 'create',
                    'uuid' : self.uuid
                  }
        print(message)
        self.send_to_server(message)
        response = json.loads(self.socket.recv(1024).decode('utf-8'))
        print(response)
        if response.get('error'):
            log_error("This uuid already has a message box")

        else:
            self.id = response.get('result')
            log_success("Message box with created successfully (ID: %s)" % str(response.get('result')))


    def List(self, uid = None):
        if uid == None:
            message = {'type' : 'list'}
        else:
            message = {'type' : 'list', 'id' : uid}

        self.send_to_server(message)
        response = json.loads(self.socket.recv(1024).decode('utf-8'))

        if response.get('error'):
            log_error(response.get('error'))
        else:
            print(response)
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
        response = json.loads(self.socket.recv(1024).decode('utf-8'))

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
        response = json.loads(self.socket.recv(1024).decode('utf-8'))
        if response.get('error'):
            log_error(response.get('error'))
        else:
            print(response)

    def Send(self, dst, msg, src = None):
        src = self.id if src == None else src
        message = { 'type'	: 'send', 
                    'src'	: src,
                    'dst'	: dst,
                    'msg'	: msg,
                    'copy'	: msg
                  }

        self.send_to_server(message)
        response = json.loads(self.socket.recv(1024).decode('utf-8'))
        print(response)


    def Recv(self, receiver, box):
        message = { 'type'	: 'recv', 
                    'id'	: receiver,  
                    'msg'	: box,
                  }

        self.send_to_server(message)
        response = json.loads(self.socket.recv(1024).decode('utf-8'))
        if response.get('error'):
            log_error(response.get('error'))
        else:
            print(response)
                

    def Receipt(self, box):
        message = { 'type'		: 'receipt', 
                    'id'		: self.id,  
                    'msg'		: box,
                    'receipt'	: "Vamos imaginar que este texto e uma assinatura"  # hint: Não é ;) 
                  }

        self.send_to_server(message)
        self.socket.settimeout(0.5)
        try:
            response = json.loads(self.socket.recv(1024).decode('utf-8'))
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
        response = json.loads(self.socket.recv(1024).decode('utf-8'))
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
        pub = getPublicKeyCC()
    except IndexError:
        log_error("Please use citizen card")
        sys.exit(-1)

    if pub != None:

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(pub)
        uuid = digest.finalize()
        uuid = int.from_bytes(uuid, byteorder='big')

    print(str(uuid) + " uuid")

    try:
        client = Client(uuid)
    except IndexError:
        log_error("Please pass a uuid as argument")
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
            client.New(result) if result else log_error("Invalid Value")

        elif x == 4:
            result = get_int(question = "User ID? ")
            client.All(result) if result else log_error("Invalid Value")

        elif x == 5:  # Send Function

            dst = get_int(question = "Destination User ID? ")

            msg = str(raw_input("Message? "))

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


