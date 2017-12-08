from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

import os
import sys



class Sym_Cyphers(object):
    """docstring for Sym_Cyphers"""
    def __init__(self, uuid, block_size = 16, key_size=256, mode="CBC"):

        self.in_file_name = str(uuid) + "_symetric.pem" 

        self.block_size = block_size
        self.key_size = key_size
        self.backend = default_backend()
        self.key =  os.urandom(self.key_size//8)
        self.iv =  os.urandom(self.block_size)
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
        text = [text[i:i+self.block_size] for i in range(0, len(text), self.block_size)]
        msg = ""
        for x in text:
            if len(x) == self.block_size:
                msg += self.encryptor.update(x)

            else:
                self.padder.update(x)
                msg = self.padder.finalize()
                msg +=  self.encryptor.update(msg) + self.encryptor.finalize()
                break

        return msg


    def decyph_text(self, text):
        text = [text[i:i+self.block_size] for i in range(0, len(text), self.block_size)]

        try:
            next_block = text[0]
        except:
            raise NameError("Passed text is empty")

        for value in range(1, len(text)):
            print(value)
            x = next_block
            if len(x) == self.block_size:

                try:
                    next_block = text[value]
                except:
                    next_block = ""
                    print("Final block")


                if len(next_block) == 0:
                    msg = self.decryptor.update(x) + self.decryptor.finalize()

                    data = self.unpadder.update(msg)
                    unpad = self.unpadder.finalize()
                    self.decifrado.write(unpad)
                    break


                msg = self.decryptor.update(x)
                self.decifrado.write(msg)

            elif len(x) != 0 and len(x) != self.block_size:
                raise NameError("len(x) != block_size") 
            else:
                break


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
    x = Sym_Cyphers( in_file=sys.argv[1], cyph_file="cifrado_AES_CBC.bmp", decyph_file="decifrado_AES_CBC.bmp", block_size = 16, key_size = 256, mode="CBC")

    x.cyph()
    x.decyph()

    x.close_all()



    
