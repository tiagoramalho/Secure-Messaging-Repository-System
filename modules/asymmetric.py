from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from symmetric import Sym_Cyphers
import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding

from getpass import getpass

from pkcs11.util.rsa import encode_rsa_public_key
import os
import sys
from OpenSSL import crypto

def derivateKey(key, salt):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC( algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend) 
    key = kdf.derive(key)
    return key, salt

def dumps(dic):
    # Padding, key, chave
    str_to_return = []

    str_to_return.append(base64.b64encode(dic["padding"]))
    str_to_return.append(base64.b64encode(dic["iv"]))
    str_to_return.append(base64.b64encode(dic["key"]))
    
    x = bytes("\n", "utf-8").join(str_to_return)
    return x

def loads(ks):
    ks = ks.split(bytes("\n", "utf-8"))

    padding = base64.b64decode(ks[0])
    iv = base64.b64decode(ks[1])
    key = base64.b64decode(ks[2])


    return {"key": key, "iv": iv, "padding": padding}


class Asy_Cyphers(object):
    """docstring for Asy_Cyphers"""
    def __init__(self, uuid): # 
        super(Asy_Cyphers, self).__init__()
        self.pub_file = str(uuid) + "_pub.pem"
        self.private_file =  str(uuid) + "_priv.pem"
        try: 



            with open(self.pub_file, "rb") as key_file:
                self.public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )  
            with open(self.private_file, "rb") as key_file:
                pw = getpass("Insert PassPhrase for Ciphering key pair: ")
                self.private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read(), passphrase=bytes(pw, "utf-8")) if pw != None else crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read()) 
                self.private_key = self.private_key.to_cryptography_key()

        except OSError as e:
            pw = getpass("Creating key pair for Ciphering. Please insert a passphrase: ")
            print("Generating key pair for cyphering")

            pw = pw if pw != None else None 
            keys = crypto.PKey()
            keys.generate_key(crypto.TYPE_RSA, 2048)
            self.save_keys(keys, pw)

            self.private_key = keys.to_cryptography_key()
            self.public_key = self.private_key.public_key()

        except crypto.Error as e:
            print("Invalid passphrase for this key_pair")
            sys.exit(-1)






    
    def getPub(self):
        public_key = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key

    def save_keys(self, keys, passphrase):
        private_file = open(self.private_file, "wb+")
        pub_file = open(self.pub_file, "wb+")
        if passphrase:
            private_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, keys, cipher="aes256", passphrase=bytes(passphrase, "utf-8")))

        else:
            private_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, keys))


        pub_file.write(crypto.dump_publickey(crypto.FILETYPE_PEM, keys))

        private_file.close()
        pub_file.close()

    def cyph(self, txt, public_key=None, padd=None):
        # Kpub  -> pertence a todos
        # kpriv -> pertence ao dono
        # T     -> texto
        #Ks     -> chave simetrica
        #encript_sim(T,Ks) encript_asim(Ks + dados, Kpub) -> confidenciabilidade hibrida
        # c= encript(T,Ks)
        #Hash(c)-> encript(Kpriv, H(c)) -> Autenticidade

        sym_cypher = Sym_Cyphers(block_size = 16,
                                key_size = 256,
                                mode="CTR")

        cypheredText = sym_cypher.cyph_text(txt)
        key = sym_cypher.key
        iv = sym_cypher.iv

        if not padd:
            padd = os.urandom(32) # padding
        
        # ks a baixo  = ks + dados
        ks = {"padding": padd, "iv": iv, "key": key}

        if public_key:
            public_key = serialization.load_pem_public_key(
                bytes(public_key, "utf-8"),
                backend=default_backend()
            )
        else: 
            public_key = self.public_key

        ciphered_key = public_key.encrypt(dumps(ks),
                                          padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(),
                                                        label=None
                                                      )
                                          )

        hibrid_data = (base64.b64encode(cypheredText) + bytes("\n", "utf-8") + base64.b64encode(ciphered_key))

        return hibrid_data

    def decyph(self, data):

        intermidiate_data = base64.b64decode(data).split(bytes("\n", "utf-8"))

        ciphered_text = base64.b64decode(intermidiate_data[0])
        ciphered_key = base64.b64decode(intermidiate_data[1])

        # ks a baixo  = ks + dados
        ks = self.private_key.decrypt(
                    ciphered_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None)
                    )
        
        ks = loads(ks)

        padd = ks.get("padding")
        ivUsed = ks.get("iv")
        keyUsed = ks.get("key")


        sym_cypher = Sym_Cyphers(block_size = 16,
                                key_size = 256,
                                mode="CTR", 
                                key = keyUsed, 
                                iv = ivUsed)

        plainText = sym_cypher.decyph_text(ciphered_text)
        return plainText, padd


if __name__ == "__main__":

    # argv 1 = RSA key size (usar 2048 ou 4096)
    # argv 2 = public file to store public key
    # argv 3 = private file to store private key
    # argv 4 = Ficheiro a cifrar


    x = Asy_Cyphers(int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4])
    x.save_keys()
    x.cyph()
    x.decyph()
