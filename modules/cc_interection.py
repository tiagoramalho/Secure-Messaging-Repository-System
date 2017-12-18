import os
import getpass
from pprint import pprint
import requests
import sys
import shutil
import datetime
import socket


from OpenSSL import crypto
import OpenSSL


from pkcs11.util.rsa import encode_rsa_public_key
from pkcs11 import Attribute, ObjectClass
from pkcs11.exceptions import TokenNotPresent
from pkcs11.exceptions import NoSuchToken
from pkcs11.util.x509 import decode_x509_certificate

import pkcs11

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives import serialization

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
            self.cert = self.get_my_cert()
            self.get_all_crls()
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


            signature = priv.sign(data, mechanism=pkcs11.Mechanism.SHA1_RSA_PKCS)

            return signature



    # Ver se significado inválido
    def validate_signature(self, data, signature, certificate):
        try:
            #Verificações por OCSP
            if self.test_internet_on() and self.crls_updated:
                #self.validate_by_ocsp()
                self.verify_certificate_chain(self.get_cert_chain(certificate), certificate)

            elif self.test_internet_on() and not self.crls_updated:
                self.get_all_crls()             #Updating crl's
                #self.validate_by_ocsp()
                self.verify_certificate_chain(self.get_cert_chain(certificate), certificate)



            verification = crypto.verify(certificate, signature, data, "sha1")
            return True
        except Exception as e:
            print("Failed encryption")
            print(e)
            raise e

            #return False
        


    # Verifica a cadeia de certificação mas não vê se foi revogado.
    def verify_certificate_chain(self, chain, cert):
        crl_list = self.get_crl_list_for_given_chain(chain)
        crl_list = self.crl_files_to_objects(crl_list)


        certificate = cert

        try:
                    
            store = crypto.X509Store()
            store.set_flags(crypto.X509StoreFlags.CRL_CHECK_ALL)

            for cert in chain:
                store.add_cert(cert)

            for crl in crl_list:
                store.add_crl(crl)

            store_ctx = crypto.X509StoreContext(store, certificate)

            store_ctx.verify_certificate()

            return True

        except Exception as e:
            raise e



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
                return cert

    # Faz download de todas as Revocation Lists
    def get_all_crls(self):

        if not self.test_internet_on():
            print("No internet connection to update CRL's")
            return
        elif self.crls_updated == True:
            return

        print("Internet connection detected. Updating CRL's...")
        all_crls = []
        path = os.path.join(self.dir, "certs")
        for file in os.listdir(path):
            if file.endswith(".pem"):
                path = os.path.join(self.dir, "certs", file)
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(path, "r").read())
                extentions = self.get_cert_extentions(cert)

                base_crl = all_crls.append(extentions["extentions"].get("base_crl", None))
                delta_crl = all_crls.append(extentions["extentions"].get("delta_crl", None))

        for crl in list(set(all_crls)):
            self.get_crl(crl)

        # This gets my certificate CRL's and delta
        path = os.path.join(self.dir, "certs", file)
        extentions = self.get_cert_extentions(self.cert)

        base_crl = extentions["extentions"].get("base_crl", None)
        delta_crl = extentions["extentions"].get("delta_crl", None)

        self.get_crl(base_crl)
        self.get_crl(delta_crl)
        # Ends here

        self.crls_updated = True


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
                if file == base_crl:
                    list_crl_chain.append(file)

                elif file == delta_crl:
                    list_crl_chain.append(file)

        return list_crl_chain






    # -----------------------------
    #       HELP Functions
    # -----------------------------

    def crl_files_to_objects(self, files):

        path = os.path.join(self.dir, "crls")
        obj_list = []
        for file in files:
            with open(os.path.join(path, file), 'rb') as f:

                obj_list.append(OpenSSL.crypto.load_crl(crypto.FILETYPE_ASN1, f.read()))
        return obj_list

    # Devolve o URI por causa da porcaria do ASN1. Vi-me obrigado  a Improvisar
    def get_URI(self, s):
        return (s.split("URI:"))[1].split("\n")[0]

    def get_crl_links(self, cert):
        base = self.get_cert_extentions(cert)["extentions"].get("base_crl")
        delta = self.get_cert_extentions(cert)["extentions"].get("delta_crl")
        return (base, delta)


    # Faz download de uma Revocation List Especifica 
    def get_crl(self,crl_link):

        if crl_link == None:
            return

        local_filename = str(crl_link.split('/')[-1])

        r = requests.get(crl_link, stream=True)
        path = os.path.join(self.dir, "crls", local_filename)
        with open(path, 'wb') as f:
            shutil.copyfileobj(r.raw, f)

        return local_filename

    # Devolve issur do certificado certificado
    def get_cert_issuer(self, cert):
        return dict(cert.get_issuer().get_components())

    # Devolve Subject do certificado certificado
    def get_cert_subject(self, cert):
        return dict(cert.get_subject().get_components())

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


if __name__ == '__main__':
    cc = CC_Interaction()
    cert = cc.get_my_cert()

    data = "ganda lol ho ganda fdp"

    signature = cc.sign(data)

    print(cc.validate_signature(data, signature, cert))







