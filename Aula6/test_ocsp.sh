#openssl x509 -noout -ocsp_uri -in my.pem 

#openssl ocsp -issuer my_chain.pem -cert my.pem -text -url http://ocsp.auc.cartaodecidadao.pt/publico/ocsp

openssl ocsp -issuer my_chain.pem -cert my.pem -url http://ocsp.auc.cartaodecidadao.pt/publico/ocsp





