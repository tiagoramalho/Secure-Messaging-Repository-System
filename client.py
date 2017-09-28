from socket import *
from log import *


class Client(object):
	"""docstring for Client"""
	def __init__(self, file_name=None):
		super(Client, self).__init__()

		# Server connection variables
		self.server_ip = "127.0.0.1"
		self.server_port = 8080
		self.socket = socket(AF_INET, SOCK_STREAM)
		self.socket.connect((self.server_ip, self.server_port))

		# Cliente informations innitialization
		if file_name == None:
			pass

		else:
			pass


		self.messageTypes = {
			'all': self.processAll,
			'list': self.processList,
			'new': self.processNew,
			'send': self.processSend,
			'recv': self.processRecv,
			'create': self.processCreate,
			'receipt': self.processReceipt,
			'status': self.processStatus
		}

	def processCreate(self):
		return "teste"

	def processList(self):
		return "teste"
		pass

	def processNew(self):
		return "teste"
		pass

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

	def send_msg(self, function=None, message=""):
		
		if function in self.messageTypes:
			to_send = {'type': function}
			msg = self.messageTypes[function](to_send=to_send)
			self.socket.sendall(msg)

		else: 
			log(logging.ERROR, 'Unknown function Client "%s"' % (function))
			return

		#self.socket.sendall(msg)
		data = self.socket.recv(1024)
		# self.socket.close()

		# print 'Received', repr(data)


def menu():
	print "Chose an option: "
	print "1 - CREATE message box"
	print "2 - LIST message boxes"
	print "3 - List NEW messages in message box"
	print "4 - List ALL messages in message box"
	print "5 - SEND a message to a message box"
	print "6 - RECEIV a specific message from a message box"
	print "7 - Send a message RECEIPT"
	print "8 - Check for message reception STATUS"


if __name__ == "__main__":


	x = Client()

	while 1:
		menu()
		try:
			x = int(input("Enter a number: "))

			if x == 1:
				processCreate()

			elif x == 2:
				processList()				

			elif x == 3:
				processNew()

			elif x == 4:
				processAll()

			elif x == 5:
				processSend()

			elif x == 6:
				processRecv()

			elif x == 7:
				processReceipt()

			elif x == 8:
				processStatus()

			else:
				pass
		except Exception as e:
			raise



	x.send_msg(function="all", message="teste")