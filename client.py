from socket import *
from log import *
import json
TERMINATOR = "\r\n"


class Client(object):
	"""docstring for Client"""
	def __init__(self):
		super(Client, self).__init__()
		self.server_ip = "127.0.0.1"
		self.server_port = 8080
		self.socket = socket(AF_INET, SOCK_STREAM)
		self.socket.connect((self.server_ip, self.server_port))


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

	def processCreate(self, to_send):
		return "teste"

	def processList(self):
		print ("aqui")
		msg = {'type' : 'list'}
		self.socket.sendall(json.dumps(msg) + TERMINATOR)
	def processNew(self, to_send):
		return "teste"
		pass

	def processAll(self, to_send):
		return "teste"
		pass

	def processSend(self, to_send):
		return "teste"
		pass

	def processRecv(self, to_send):
		return "teste"
		pass

	def processReceipt(self, to_send):
		return "teste"
		pass

	def processStatus(self, to_send):
		return "teste"
		pass


	def send_msg(self, function=None, message=""):

		if function in self.messageTypes:
			self.processList()

		else:
			log(logging.ERROR, 'Unknown function Client "%s"' % (function))
			return

		#self.socket.sendall(msg)
		data = self.socket.recv(1024)
		# self.socket.close()

		# print 'Received', repr(data)




if __name__ == "__main__":
	clien = Client()
	clien.send_msg(function="list", message="teste")
