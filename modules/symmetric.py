from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

import os
import sys



class Sym_Cyphers(object):
    """docstring for Sym_Cyphers"""
    def __init__(self, block_size = 16, key_size=256, mode="CBC", key = None, iv = None):

        #self.in_file_name = str(uuid) + "_symetric.pem" 

        self.block_size = block_size
        self.key_size = key_size
        self.backend = default_backend()
        self.key =  os.urandom(self.key_size//8) if key == None else key
        self.iv =  os.urandom(self.block_size) if iv == None else iv
        self.padder = padding.PKCS7(self.block_size*8).padder()
        self.unpadder = padding.PKCS7(self.block_size*8).unpadder()

        if mode == "CBC":
            self.mode = modes.CBC(self.iv)
        elif mode == "ECB":
            self.mode = modes.ECB()
        else:
            raise
            print("ERROR invalid cypher MODE")

        self.cipher = Cipher(algorithms.AES(self.key), self.mode, backend=self.backend)
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()

    def cyph_text(self, text):
        print("TEXT")
        print(text)
        msg = b""

        dataPadded = self.padder.update(text)
        dataPadded += self.padder.finalize()
        print(dataPadded)

        msg =  self.encryptor.update(dataPadded) + self.encryptor.finalize()

        return msg


    def decyph_text(self, text):
        
        print("decyph text")
        msg = b""
        print(text)
        msg = self.decryptor.update(text) + self.decryptor.finalize()
        print(msg)

        data = self.unpadder.update(msg)
        unpad = data + self.unpadder.finalize()



        return unpad 


    def cyph_file(self):
        self.open_cyph_files()

        while 1:
            x = self.infile.read(self.block_size)
            if len(x) == self.block_size:
                self.outfile.write(self.encryptor.update(x))

            else:
                self.padder.update(x)
                msg = self.padder.finalize()

                x = self.encryptor.update(msg) + self.encryptor.finalize()

                self.outfile.write(x)
                break
        self.close_all()
        

    def decyph_file(self):
        self.open_decyph_files()

        next_block = self.outfile.read(self.block_size)
        while 1:
            x = next_block
            if len(x) == self.block_size:

                next_block = self.outfile.read(self.block_size)

                if len(next_block) == 0:
                    msg = self.decryptor.update(x) + self.decryptor.finalize()

                    data = self.unpadder.update(msg)
                    unpad = self.unpadder.finalize()
                    self.decifrado.write(unpad)
                    break


                msg = self.decryptor.update(x)
                self.decifrado.write(msg)

            else:
                break
        self.close_all()

    def open_cyph_files(self):
        self.close_all()

        self.infile = open(self.in_file_name, "rb")
        self.outfile = open(self.cyph_file_name,"wb+")


    def open_decyph_files(self):
        self.close_all()

        self.outfile = open(self.cyph_file_name,"rb")
        self.decifrado = open(self.decyph_file_name,"wb+")


    def close_all(self):
        try:
            self.infile = self.infile.close()
        except Exception as e:
            pass

        try:
            self.outfile = self.outfile.close()
        except Exception as e:
            pass

        try:
            self.decifrado = self.decifrado.close()
        except Exception as e:
            pass

if __name__ == "__main__":
    x = Sym_Cyphers()
    msg = "salhdlsakjhdjkashjkdhsajkhdjkashjkdhajkshdjkh ashdjksahd o branco "
    f = bytes(msg, 'utf-8')
    print(f)
    enc = x.cyph_text(f)
    dec = x.decyph_text(enc)
    print(dec)
    print(dec.decode('utf-8'))




    
