from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from symmetric import Sym_Cyphers
import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import os
import sys

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
    def __init__(self, key_size, pub_file, private_file, file_to_cyph):
        super(Asy_Cyphers, self).__init__()

        self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

        self.pub_file = pub_file
        self.private_file = private_file

        self.file_to_cyph = file_to_cyph
        self.cyphed_file = self.file_to_cyph+"_cyph_AES_CBC"
        self.decyphed_file = self.file_to_cyph+"_decyph_AES_CBC"

        self.key_size = 256

        self.sim_cypher = Sim_Cypher( 	in_file=self.file_to_cyph,
                                        cyph_file=self.cyphed_file,
                                        decyph_file=self.decyphed_file,
                                        block_size = 16,
                                        key_size = self.key_size,
                                        mode="CBC")



    def save_keys(self):
        private_file = open(self.private_file, "wb+")
        pub_file = open(self.pub_file, "wb+")

        private_key = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
        )

        public_key = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        )


        private_file.write(private_key)
        pub_file.write(public_key)

        private_file.close()
        pub_file.close()

    def cyph(self):
        # Kpub  -> pertence a todos
        # kpriv -> pertence ao dono
        # T     -> texto
        #Ks     -> chave simetrica

        #encript_sim(T,Ks) encript_asim(Ks + dados, Kpub) -> confidenciabilidade hibrida


        # c= encript(T,Ks)
        #Hash(c)-> encript(Kpriv, H(c)) -> Autenticidade

        self.sim_cypher.cyph_file()
        key = self.sim_cypher.key
        iv = self.sim_cypher.iv
        padd = os.urandom(32) # padding
        # ks a baixo  = ks + dados

        ks = {"padding": padd, "iv": iv, "key": key}


        ciphered_key = self.public_key.encrypt( dumps(ks),
                                              padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                            algorithm=hashes.SHA1(),
                                                            label=None
                                                          )
                                            )


        ciphered_text = open(self.cyphed_file, "rb").read()

        hibrid_data = open("intermidiate_data", "wb+")
        hibrid_data.write(base64.b64encode(ciphered_text) + bytes("\n", "utf-8") + base64.b64encode(ciphered_key))
        hibrid_data.close()
        




    def decyph(self):
        intermidiate_data = open("intermidiate_data", "rb").read().split(bytes("\n", "utf-8"))
        intermidiate_data = intermidiate_data

        ciphered_text = base64.b64decode(intermidiate_data[0])
        ciphered_key = base64.b64decode(intermidiate_data[1])

        # ks a baixo  = ks + dados
        ks = self.private_key.decrypt(
                    ciphered_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA1()),
                        algorithm=hashes.SHA1(),
                        label=None)
                    )
        
        ks = loads(ks)

        iv = ks.get("iv")
        key = ks.get("key")

        self.sim_cypher.iv = iv
        self.sim_cypher.key = key

        self.sim_cypher.decyph_file()



if __name__ == "__main__":

    # argv 1 = RSA key size (usar 2048 ou 4096)
    # argv 2 = public file to store public key
    # argv 3 = private file to store private key
    # argv 4 = Ficheiro a cifrar


    x = Asy_Cyphers(int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4])
    x.save_keys()
    x.cyph()
    x.decyph()
