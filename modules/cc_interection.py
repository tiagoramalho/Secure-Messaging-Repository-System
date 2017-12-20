import os
import getpass
from pprint import pprint
import requests
import sys
import shutil
import datetime
import socket

import asn1crypto.x509


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

from oscrypto import asymmetric
from ocspbuilder import OCSPRequestBuilder


# Testa connectividade
def test_internet_on():
    try:
        host = socket.gethostbyname("www.google.com")
        s = socket.create_connection((host, 80), 2)
        return True
    except Exception as e:
        pass
    return False







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
            #self.get_all_crls()
        except (TokenNotPresent, NoSuchToken, IndexError):
            print("Please insert the Citizen Card\n Exiting...")
            raise e
            #sys.exit(-1)
        except Exception as e:
            raise e



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
        if test_internet_on() and not self.crls_updated:
            self.get_all_crls()             #Updating crl's

        try:
            chain = self.get_cert_chain(certificate)
            ocsp_list = []
            crl_list = []
            all_crl_list = []

            for i in range(0, len(chain)):
                base, delta = self.get_crl_links(chain[i])

                if self.get_ocsp_link(chain[i]):
                    ocsp_list.append([chain[i],chain[i+1]])
                else:
                    crl_list.append(self.get_crl_name_from_link(base))
                    crl_list.append(self.get_crl_name_from_link(delta))

                all_crl_list.append(self.get_crl_name_from_link(base))
                all_crl_list.append(self.get_crl_name_from_link(delta))

            crl_list = list(filter(lambda a: a != None, crl_list))
            all_crl_list = list(filter(lambda a: a != None, all_crl_list))


            #Verificações por OCSP + CRL List Restante

            if test_internet_on():
                if False in [self.ocsp_validation(x[0], x[1]) for x in ocsp_list]:
                    raise NameError('Certificate invalid: OCSP verification')
                self.verify_certificate_chain(certificate, chain, crl_list)

            else: 
                self.verify_certificate_chain(certificate, chain, all_crl_list)





            verification = crypto.verify(certificate, signature, data, "sha1")
            return True
        except Exception as e:
            print("Failed encryption")
            raise e

            #return False
        


    # Verifica a cadeia de certificação mas não vê se foi revogado.
    def verify_certificate_chain(self, cert, chain, crl_list):
        crl_list = self.crl_files_to_objects(crl_list)

        print(crl_list)

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

        if not test_internet_on():
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




    def ocsp_validation(self, subject_cert, issuer_cert):
        ocsp_link = self.get_ocsp_link(subject_cert)

        subject_cert = asymmetric.load_certificate(
            crypto.dump_certificate(
                crypto.FILETYPE_ASN1,
                subject_cert
                )
            )

        issuer_cert = asymmetric.load_certificate(  
            crypto.dump_certificate(
                crypto.FILETYPE_ASN1,
                issuer_cert
            ))
        builder = OCSPRequestBuilder(subject_cert, issuer_cert)
        ocsp_request = builder.build()
        r = requests.post(
            ocsp_link,
            data = ocsp_request.dump(),
            headers={"Content-Type": "application/ocsp-request"}
        )

        resposta = asn1crypto.ocsp.OCSPResponse.load(r.content)

        return "good" == resposta['response_bytes']['response'].parsed['tbs_response_data']["responses"][0]["cert_status"].name




    # -----------------------------
    #       HELP Functions
    # -----------------------------

    def get_crl_name_from_link(self, link):
        try:
            return link.split('/')[-1]
        except Exception as e:
            return None


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

    def get_ocsp_link(self, certificate):
        try:
            return self.get_cert_extentions(certificate)["extentions"]["ocsp"]
        except Exception as e:
            return None








if __name__ == '__main__':
    cc = CC_Interaction()
    cert = cc.get_my_cert()

    chain = cc.get_cert_chain(cert)



    data = "ganda lol ho ganda fdp"

    signature = cc.sign(data)

    print(cc.validate_signature(data, signature, cert))







