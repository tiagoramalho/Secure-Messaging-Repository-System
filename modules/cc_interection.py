import os
import getpass
from pprint import pprint
import requests
import sys
import shutil
import datetime
import socket
import base64


from OpenSSL import crypto
import OpenSSL


from pkcs11.util.rsa import encode_rsa_public_key
from pkcs11 import Attribute, ObjectClass
from pkcs11.exceptions import TokenNotPresent
from pkcs11.exceptions import NoSuchToken
import pkcs11

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import x509

import time




class CC_Interaction(object):
    """docstring for cc_interaction"""
    def __init__(self):
        super(CC_Interaction, self).__init__()
        self.dir = os.path.dirname(os.path.realpath(__file__))
        try:
            print("Getting token_label...")
            self.lib = pkcs11.lib("/usr/lib/opensc-pkcs11.so")
            self.token = self.lib.get_token(token_label="Auth PIN (CARTAO DE CIDADAO)")
            self.user_pin = getpass.getpass("PIN ?")
            self.crls_updated = False
            self.get_my_cert()
#            self.get_all_crls()
        except (TokenNotPresent, NoSuchToken, IndexError):
            print("Please insert the Citizen Card\n Exiting...")
            raise e
            #sys.exit(-1)
        except Exception as e:
            raise e

    # Testa connectividade
    def test_internet_on(self):
        try:
            host = socket.gethostbyname("www.google.com")
            s = socket.create_connection((host, 80), 2)
            return True
        except Exception as e:
            pass
        return False

    #Funções Ramalhão
    def getPublicKeyCC(self):
        with self.token.open(user_pin = str(self.user_pin)) as session:
            pub = session.get_key(pkcs11.constants.ObjectClass.PUBLIC_KEY,
                pkcs11.KeyType.RSA, "CITIZEN AUTHENTICATION CERTIFICATE")
            pem = encode_rsa_public_key(pub)
        return pem

    def get_pubkey_hash_int(self):
        pub = self.getPublicKeyCC()
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(pub)
        uuid = digest.finalize()
        uuid = int.from_bytes(uuid, byteorder='big')
        return uuid

    # Assina tem de ser alterada e dividida em duas TODO
    def sign(self, data):

        with self.token.open(user_pin = str(self.user_pin)) as session:

            priv = session.get_key(pkcs11.constants.ObjectClass.PRIVATE_KEY,
                pkcs11.KeyType.RSA, "CITIZEN AUTHENTICATION KEY")

            print(priv)

            signature = priv.sign(data, mechanism=pkcs11.Mechanism.SHA1_RSA_PKCS)
            print(type(signature))

            pub = session.get_key(pkcs11.constants.ObjectClass.PUBLIC_KEY,
                pkcs11.KeyType.RSA, "CITIZEN AUTHENTICATION CERTIFICATE")
            print(pub)

            print(pub.verify(data, signature, mechanism=pkcs11.Mechanism.SHA1_RSA_PKCS))

    # Verifica a cadeia de certificação mas não vê se foi revogado.
    def verify_certificate_chain(self, chain, cert):

        certificate = cert

        try:
                    
            store = crypto.X509Store()

            for cert in chain:
                store.add_cert(cert)

            store_ctx = crypto.X509StoreContext(store, certificate)

            store_ctx.verify_certificate()

            return True

        except Exception as e:
            print(e)
            return False

    # Devolve o URI por causa da porcaria do ASN1. Vi-me obrigado  a Improvisar
    def get_URI(self, s):
        return (s.split("URI:"))[1].split("\n")[0]


    # devolve as extensões na forma de um dicionário {"extentions": {chave: valor}}
    def get_cert_extentions(self, cert):
        info = {}
        info["extentions"] = {} 
        for value in range(0,cert.get_extension_count()):
            c = cert.get_extension(value)
            name = c.get_short_name()

            try:
                c.__str__()
            except Exception as e:
                continue

            if name == b"freshestCRL":
                info["extentions"]["delta_crl"]  = self.get_URI(c.__str__())

            elif name == b"crlDistributionPoints":
                info["extentions"]["base_crl"]  = self.get_URI(c.__str__())

            elif name == b"authorityInfoAccess":
                info["extentions"]["ocsp"]  = self.get_URI(c.__str__())
            else:
                info["extentions"][c.get_short_name()]  = c.__str__()


        return info

    # Devolve issur do certificado certificado
    def get_cert_issuer(self, cert):
        return dict(cert.get_issuer().get_components())

    # Devolve Subject do certificado certificado
    def get_cert_subject(self, cert):
        return dict(cert.get_subject().get_components())


    def ocsp(self, cert): 
        with self.token.open() as session:
            try:
                uri = self.get_cert_extentions(cert)["ocsp"]
            except:
                return True

        #TODO get_ocsp


    # Devolve a cadeia de certificação.
    def get_cert_chain(self, cert):
        issuer = self.get_cert_issuer(cert)
        subject = self.get_cert_subject(cert)
        found = False
        chain = [cert]

        while issuer != subject:
            path = os.path.join(self.dir, "certs")
            for file in os.listdir(path):
                if file.endswith(".pem"):
                    path = os.path.join(self.dir, "certs", file)
                    cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(path, "r").read())
                    subject = self.get_cert_subject(cert)
                    if issuer == subject:
                        issuer = self.get_cert_issuer(cert)
                        found = True
                        chain.append(cert)
                        break
            if found:
                found = False
            else:
                return False

        if issuer == subject:
            return chain
        return False

    # Devolve o próprio certificado
    def get_my_cert(self):
        with self.token.open(user_pin = str(self.user_pin)) as session:
            for cert in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE,}):
                cert = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_ASN1,
                    cert[Attribute.VALUE],
                )
                self.cert = cert
                return cert

    #devolve o cert em formato PEM
    def getCertPem(self):
        print("ENTROY")
        return base64.b64encode(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, self.get_my_cert()))
    # Faz download de todas as Revocation Lists
    def get_all_crls(self):

        if not self.test_internet_on():
            print("No internet connection to update CRL's")
            return
        elif self.crls_updated == True:
            return

        print("Internet connection detected. Updating CRL's...")

        path = os.path.join(self.dir, "certs")
        for file in os.listdir(path):
            if file.endswith(".pem"):
                path = os.path.join(self.dir, "certs", file)
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(path, "r").read())
                extentions = self.get_cert_extentions(cert)

                base_crl = extentions["extentions"].get("base_crl", None)
                delta_crl = extentions["extentions"].get("delta_crl", None)

                self.get_crl(base_crl)
                self.get_crl(delta_crl)


        path = os.path.join(self.dir, "certs", file)
        extentions = self.get_cert_extentions(self.cert)

        base_crl = extentions["extentions"].get("base_crl", None)
        delta_crl = extentions["extentions"].get("delta_crl", None)

        self.get_crl(base_crl)
        self.get_crl(delta_crl)

        print("Done")
        self.crls_updated = True

    # Faz download de uma Revocation List Especifica 
    def get_crl(self,crl_link):

        if crl_link == None:
            return

        local_filename = str(crl_link.split('/')[-1])

        print(crl_link)
        r = requests.get(crl_link, stream=True)
        path = os.path.join(self.dir, "crls", local_filename)
        with open(path, 'wb') as f:
            shutil.copyfileobj(r.raw, f)

        return local_filename

    def get_crl_links(self, cert):
        base = self.get_cert_extentions(cert)["extentions"].get("base_crl")
        delta = self.get_cert_extentions(cert)["extentions"].get("delta_crl")
        #print ((base, delta))
        return (base, delta)


    def get_crl_list_for_given_chain(self, chain):
        list_crl_chain = []
        for cert in chain:
            path = os.path.join(self.dir, "crls")
            for file in os.listdir(path):
                base_crl, delta_crl = self.get_crl_links(cert)

                if base_crl:
                    base_crl = base_crl.split('/')[-1]

                if delta_crl:
                    delta_crl = delta_crl.split('/')[-1]
                #print ((base_crl, delta_crl))
                if file == base_crl:
                    list_crl_chain.append(file)

                elif file == delta_crl:
                    list_crl_chain.append(file)

        return list_crl_chain

    def crl_files_to_objects(self, files):
        path = os.path.join(self.dir, "crls")
        obj_list = []
        for file in files:
            with open(os.path.join(path, file), 'wb') as f:
                obj_list.append()



    def a_lot_of_functions_here(self): # This has a lot of info. I recommend changes

        """
        if os.path.isfile(local_filename):
            with open(local_filename, 'rb') as f:
                crl = OpenSSL.crypto.load_crl(crypto.FILETYPE_ASN1, f.read()).to_cryptography()
                


                time = crl.next_update
                print(time.strftime("%Y-%m-%d %H:%M:%S"))
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

                return 

        """
        i = 0
        with self.token.open(user_pin = str(self.user_pin)) as session:
            chain = open("my_chain.pem", "wb")

            for cert in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE,}):
                i = i + 1
                print("--------------------------\nCertificado Nmr " + str(i) + "\n--------------------------")
                cert = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_ASN1,
                    cert[Attribute.VALUE],
                )
                info = {}

                info["subject"] = dict(cert.get_subject().get_components())
                info["issuer"]  = dict(cert.get_issuer().get_components())
                info["extentions"]  = {}

                for value in range(0,cert.get_extension_count()):
                    try:

                        c = cert.get_extension(value)
                        info["extentions"][c.get_short_name()]  = c.__str__()

                    except Exception as e:
                        pass
                        #print("{0} failed".format(value))

                # utf8 data
                for key, value in info.items():
                    for key1, value1 in value.items():
                        try:
                            info[key][key1] = value1.decode("UTF-8")
                        except Exception as e:
                            pass



                pprint(info)

                print("\n---------------------\nCRLS e OCSP\n---------------------\n")
                try:
                    print(self.get_URI(info["extentions"][b"freshestCRL"]))
                except Exception as e:
                    print("No CRL DELTA")
                    
                try:
                    print(self.get_URI(info["extentions"][b"crlDistributionPoints"]))
                except Exception as e:
                    print("No CRL")
                    
                try:
                    print(self.get_URI(info["extentions"][b"authorityInfoAccess"])) 
                except Exception as e:
                    print("No OCSP")
                


                if i == 1:
                    x = open("my.pem", "wb")
                    x.write(OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM,
                        cert,
                    ))
                    x.close()
                chain.write(OpenSSL.crypto.dump_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    cert,
                ))


                print("\nImportant data about certificate:")
                print("Has expired? {0}".format(cert.has_expired()))
                print("Is valid? {0}\n".format(self.verify_certificate_chain(self.cert_chain, cert)))
                
                #break

            chain.close()




if __name__ == '__main__':
    cc = CC_Interaction()

    cert = cc.get_my_cert()
    chain = cc.get_cert_chain(cert)

    cc.get_all_crls()
    print(chain)
    print(cc.get_crl_list_for_given_chain(chain))

    #cc.validate_by_crl(cc.cert_chain, cert)







