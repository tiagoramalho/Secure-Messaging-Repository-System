import os
import getpass
from pprint import pprint
import urllib3 as urllib2
import requests
import sys

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


class CC_Interaction(object):
    """docstring for cc_interaction"""
    def __init__(self):
        super(CC_Interaction, self).__init__()
        try:
            self.lib = pkcs11.lib("/usr/lib/opensc-pkcs11.so")
            print("Getting token_label...")
            self.token = self.lib.get_token(token_label="Auth PIN (CARTAO DE CIDADAO)")
            self.user_pin = getpass.getpass("PIN ?")

        except (TokenNotPresent, NoSuchToken, IndexError):
            print("Please insert the Citizen Card\n Exiting...")
            sys.exit(-1)
        except Exception as e:
            raise e


    def test_internet_on():
        try:
            urllib2.urlopen('www.google.com', timeout=1)
            return True
        except urllib2.URLError as err: 
            return False

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

    def sign():

        with self.token.open(user_pin = str(self.user_pin)) as session:

            priv = session.get_key(pkcs11.constants.ObjectClass.PRIVATE_KEY,
                pkcs11.KeyType.RSA, "CITIZEN AUTHENTICATION KEY")

            print(priv)



            signature = priv.sign(data, mechanism= pkcs11.Mechanism.SHA1_RSA_PKCS)
            print(type(signature))

            pub = session.get_key(pkcs11.constants.ObjectClass.PUBLIC_KEY,
                pkcs11.KeyType.RSA, "CITIZEN AUTHENTICATION CERTIFICATE")
            print(pub)

            print(pub.verify(data, signature, mechanism=pkcs11.Mechanism.SHA1_RSA_PKCS))


    def _verify_certificate_chain(cert):

        certificate = cert

        try:
                    
            store = crypto.X509Store()

            for file in os.listdir("certs"):
                if file.endswith(".pem"):
                    path = os.path.join("certs", file)
                    #print("adding " + file)

                    _cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(path, "r").read())
                    store.add_cert(_cert)


            store_ctx = crypto.X509StoreContext(store, certificate)

            store_ctx.verify_certificate()

            return True

        except Exception as e:
            print(e)
            return False


    def get_URI(s):
        return (s.split("URI:"))[1].split("\n")[0]


    def a_lot_of_functions_here(): # This has a lot of info. I recommend changes
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
                            """
                            print(value1)
                            raise e
                            """


                pprint(info)
                try:
                    print(get_URI(info["extentions"][b"freshestCRL"]))
                except Exception as e:
                    pass
                try:
                    print(get_URI(info["extentions"][b"crlDistributionPoints"]))
                except Exception as e:
                    pass        
                try:
                    print(get_URI(info["extentions"][b"authorityInfoAccess"])) 
                except Exception as e:
                    pass        
                


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
                print("Is valid? {0}\n".format(_verify_certificate_chain(cert)))
                


                #break

            chain.close()


if __name__ == '__main__':
    cc = CC_Interaction()

