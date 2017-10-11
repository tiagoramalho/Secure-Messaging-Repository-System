#!/usr/bin/env python
# -*- coding: utf-8 -*-

from socket import *
from log import *
import json
import os

import sys

from random import randint


TERMINATOR = "\r\n"

def get_int(question):
	try:
		return int(input(question))
	except:
		return None


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





	def get_self_ID(self):
		"""
			Returns message box ID for the client UUID
			Returns None if it doesn't exist
		"""

		message = {'type' : 'list'}
		self.send_to_server(message)
		response = json.loads(self.socket.recv(1024))

		if not response.get('error'):
			for x in response.get('result'):
				if self.uuid == int(x.get('description').get('uuid')):
					log_info("You have a message box already registered (ID: %s)" % x.get('id'))
					return int(x.get('id'))


		log_info("You don't have a message box yet.")
		return None



	def send_to_server(self, message):
		self.socket.sendall(json.dumps(message) + TERMINATOR)

	def Create(self):
		message = { 'type' : 'create',
			   		'uuid' : self.uuid
			  	  }

		self.send_to_server(message)
		response = json.loads(self.socket.recv(1024))

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
		response = json.loads(self.socket.recv(1024))

		if response.get('error'):
			log_error(response.get('error'))
		else:
			print response
			try:
				for x in response.get('result'):
					print x
			except Exception as e:
				log_info("Id does not exist")


	def New(self, user_id):
		message = { 'type' : 'new', 
	   				'id' : user_id
	  	  		  }
		
		self.send_to_server(message)
		response = json.loads(self.socket.recv(1024))

		if response.get('error'):
			log_error(response.get('error'))

		elif len(response.get('result')) == 0:
			log_info("No new messages to show")

		else:
			for x in response.get('result'):
				print x


	def All(self, uid):
				message = {'type' : 'all', 'id' : uid}
				self.send_to_server(message)
				response = json.loads(self.socket.recv(1024))
				if response.get('error'):
						log_error(response.get('error'))
				else:
						print response

	def Send(self, dst, src, msg):
		message = { 'type'	: 'send', 
	   				'src'	: src,
	   				'dst'	: dst,
	   				'msg'	: msg,
	   				'copy'	: msg
	  	  		  }

	  	self.send_to_server(message)
		response = json.loads(self.socket.recv(1024))
		print response


	def Recv(self, sender, boxId):
		message = { 'type'	: 'recv', 
	   				'id'	: sender,  
	   				'msg'	: boxId,
	  	  		  }

	  	self.send_to_server(message)
		response = json.loads(self.socket.recv(1024))
		if response.get('error'):
			log_error(response.get('error'))
		else:
			print response
			

	def Receipt(self):

		return "teste"
		pass

	def Status(self):
		return "teste"
		pass



def menu():
	print "\nChoose an option: "
	print "1 - CREATE message box"
	print "2 - LIST message boxes"
	print "3 - List NEW messages in message box"
	print "4 - List ALL messages in message box"
	print "5 - SEND a message to a message box"
	print "6 - RECEIV a specific message from a message box"
	print "7 - Send a message RECEIPT"
	print "8 - Check for message reception STATUS"
	print "0 - EXIT"


if __name__ == "__main__":

	try:
		client = Client(sys.argv[1])
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
			if uid == None:
				client.List()
			else:
				client.List(uid)

		elif x == 3:
			result = get_int(question = "User ID? ")
			client.New(result) if result else log_error("Invalid Value")

		elif x == 4:
			result = get_int(question = "User ID? ")
			client.All(result) if result else log_error("Invalid Value")

		elif x == 5:

			src = get_int(question = "Source Message Box ID? ")

			dst = get_int(question = "Destination User ID? ")
			
			msg = str(raw_input("Message? "))

			if dst == None:
				log_error("Invalid Destination ID")

			if src == None:
				log_error("Invalid Source ID")

			if msg == None:
				log_error("Invalid Message")


			if dst == None or src == None or msg == None:
				continue
			else:
				client.Send(dst, src, msg)


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
			user_id = get_int(question = "Sender User ID? ")
			client.Receipt()

		elif x == 8:
			client.Status()

		elif x == 0:
			break

		else:
			continue



	client.socket.close()
	print "byee :) "


