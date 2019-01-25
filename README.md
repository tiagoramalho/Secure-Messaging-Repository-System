# Secure Messaging Repository System :closed_lock_with_key: :email:

University Project ( Class: Security )

## Problem
The objective of this project is to develop a system enabling users to ex-change messages asynchronously. Messages are sent and received through a non-trustworthy central repository, which keeps messages for users until they fetch them. The resulting system is composed by a Rendezvous Point, or Server, and several clients exchanging messages. The system should be designed to support the following security features:

- Message confidentiality, integrity and authentication
- Message delivery confirmation
- Identity preservation


## Requirements

You have two option for install requirements:

1. __(Python3 required)__ ` pip install -r ./requirements.txt `

2. __(virtualenv required)__ ` ./create_venv.sh ` ` source venv/bin/activate `

You will also need a middleware of the Portuguese Citizenship Card because to ensure identity preservation all messages are signed using CC's Authentication Key.

## Deployment

First, it is needed to run the server:

```bash
 	# On project dir
	python Server/server.py 
```

After, for open one client interface, it is needed to plug the Citizenship Card and next:

```bash
 	# On project dir
	python Client/client.py 
```

