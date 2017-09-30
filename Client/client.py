from socket import *
from log import *
import json
import os
from random import randint


TERMINATOR = "\r\n"

def get_int(question):
	try:
		return int(input(question))
	except:
		return None


class Client(object):
	"""docstring for Client"""
	def __init__(self, file_name="A"):
		super(Client, self).__init__()

		# Server connection variables
		self.server_ip = "127.0.0.1"
		self.server_port = 8080
		self.socket = socket(AF_INET, SOCK_STREAM)
		self.socket.connect((self.server_ip, self.server_port))


		# Client informations innitialization

		try:
			file = open(file_name, "r")
			self.uuid = int(file.read())
			file.close()	

		except Exception as e:
			try:
				file = open(file_name, "w+")
				x= randint(20, 100)
				file.write( str(x) )

				self.uuid = x
				
				file.close()

			except Exception as e:
				print "Something went wrong creating/opening UUID"
				raise







	def send_to_server(self, message):
		self.socket.sendall(json.dumps(message) + TERMINATOR)

	def processCreate(self):
		message = { 'type' : 'create', 
			   	    'uuid' : self.uuid
			  	  }

		self.send_to_server(message)
		response = json.loads(self.socket.recv(1024))

		if response.get('error'):
			log_error(response.get('error'))

		else:
			log_success("Message box created successfully :)")



	def processList(self):
		message = {'type' : 'list'}
		self.send_to_server(message)  # Simplifiquei isto velho

		return


	def processNew(self, user_id):
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


	def processAll(self):
		return "teste"
		pass

	def processSend(self):
		return "teste"
		pass

	def processRecv(self):
		return "teste"
		pass

	def processReceipt(self):
		return "teste"
		pass

	def processStatus(self):
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


	client = Client("A")

	while 1:
		menu()
		x = None

		try:
			x = int(input("Opt: "))
		except Exception as e:
			print("Must be an integer")
			

		if x == 1:
			client.processCreate()

		elif x == 2:
			client.processList()				

		elif x == 3:
			result = get_int(question = "User ID? ")
			client.processNew(result) if result else log_error("Invalid Value")

		elif x == 4:
			client.processAll()

		elif x == 5:
			client.processSend()

		elif x == 6:
			client.processRecv()

		elif x == 7:
			client.processReceipt()

		elif x == 8:
			client.processStatus()

		elif x == 0:
			break

		else:
			continue



	client.socket.close()
	print "byee :) "



# Might be needed 

"""

		data = self.socket.recv(1024)

"""