import os
import pkcs11
import getpass
import OpenSSL
from OpenSSL import crypto
from pkcs11 import Attribute, ObjectClass
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pprint import pprint



print("Getting token_label...")

lib = pkcs11.lib("/usr/lib/opensc-pkcs11.so")
token = lib.get_token(token_label="Auth PIN (CARTAO DE CIDADAO)")

data = b"Testing this piece of data"

"""
user_pin = ""


if user_pin == "":
    user_pin = getpass.getpass("PIN ?")

"""

user_pin = "8958"

def sign():

    with token.open(user_pin = str(user_pin)) as session:

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

with token.open(user_pin = str(user_pin)) as session:

    for cert in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE,}):

        cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_ASN1,
            cert[Attribute.VALUE],
        )
        info = {}

        info["subject"] = dict(cert.get_subject().get_components())
        info["issuer"]  = dict(cert.get_issuer().get_components())

        for key, value in info.items():
            for key1, value1 in value.items():
                info[key][key1] = value1.decode("UTF-8")

        pprint(info)


        print("-----------\nImportant data:\n-----------")
        print("Has expired? {0}".format(cert.has_expired()))

        

        print("Is valid? {0}\n".format(_verify_certificate_chain(cert)))


