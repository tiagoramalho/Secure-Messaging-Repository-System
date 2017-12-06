#!/usr/bin/env python
# -*- coding: utf-8 -*-

from socket import *
from log import *
import json
import os
from os import path
import sys

from random import randint
#---------------------------------------------- 

sys.path.append(path.join(path.dirname(path.realpath(__file__)),'../modules/'))
from cc_interection import CC_Interaction
from asymmetric import Asy_Cyphers 
from symmetric import Sym_Cyphers 

TERMINATOR = "\r\n"

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
        self.id = self.get_self_ID()
    

        self.privShared = None #se poder usar o parameter como tenho posso ja por aqui
        self.pubShared = None
        self.sharedKey = None

        #assimetrica gerada por nos (nao do cc)
        if not self.id:
            #pedir informaçoes ao utilizador como por exemplo key size
            pass
        
            self.AsySize = 2048
            self.AsyCypher = Asy_Cyphers
        else:
            #fazer load das informaçoes dele ?
            pass

        if not self.id:
            log_info("Creating message box...")
            self.Create()

        




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
        msgID = randomMsgId() 
        #falta a parte de assinal este msgID
        self.listMsgID.append(msgID) 
         
        message = { 'type' : 'create',
                    'uuid' : self.uuid,
                    'randomId': msgID
                  }
        print(message)
        self.send_to_server(message)
        response = json.loads(self.socket.recv(1024).decode('utf-8'))
        #verificar o msgID se esta na lista de enviados? e verificar assinatura
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
        client = Client()
        pub = client.cc.get_pubkey_hash_int() #Tem de ser alterado
        
    except Exception as e:
        raise e
    print(client.uuid)

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


