from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from symmetric import Sym_Cyphers
import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from pkcs11.util.rsa import encode_rsa_public_key
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
    def __init__(self, uuid):
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
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )

        except Exception as e:
            print("exception")
            self.private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=4096,
                    backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            self.save_keys()



    
    def getPub(self):
        public_key = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_key)

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

    def cyph(self, txt):
        # Kpub  -> pertence a todos
        # kpriv -> pertence ao dono
        # T     -> texto
        #Ks     -> chave simetrica
        #encript_sim(T,Ks) encript_asim(Ks + dados, Kpub) -> confidenciabilidade hibrida
        # c= encript(T,Ks)
        #Hash(c)-> encript(Kpriv, H(c)) -> Autenticidade

        sym_cypher = Sym_Cyphers(block_size = 16,
                                key_size = 256,
                                mode="CBC")
        cypheredText = sym_cypher.cyph_text(txt)
        print("texto cifrado assimetrico")
        print(cypheredText)
        key = sym_cypher.key
        iv = sym_cypher.iv
        padd = os.urandom(32) # padding
        # ks a baixo  = ks + dados

        ks = {"padding": padd, "iv": iv, "key": key}


        ciphered_key = self.public_key.encrypt(dumps(ks),
                                              padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                            algorithm=hashes.SHA256(),
                                                            label=None
                                                          )
                                            )
        hibrid_data = (base64.b64encode(cypheredText) + bytes("\n", "utf-8") + base64.b64encode(ciphered_key))

        return hibrid_data 
    def decyph(self, data):
        intermidiate_data = data.split(bytes("\n", "utf-8"))
        intermidiate_data = intermidiate_data

        ciphered_text = base64.b64decode(intermidiate_data[0])
        print("decypher text")
        print(ciphered_text)
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

        ivUsed = ks.get("iv")
        keyUsed = ks.get("key")

        sym_cypher = Sym_Cyphers(block_size = 16,
                                key_size = 256,
                                mode="CBC", 
                                key = keyUsed, 
                                iv = ivUsed)

        plainText = sym_cypher.decyph_text(ciphered_text)
        return plainText


if __name__ == "__main__":

    # argv 1 = RSA key size (usar 2048 ou 4096)
    # argv 2 = public file to store public key
    # argv 3 = private file to store private key
    # argv 4 = Ficheiro a cifrar


    x = Asy_Cyphers(int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4])
    x.save_keys()
    x.cyph()
    x.decyph()
