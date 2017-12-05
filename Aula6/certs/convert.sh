
#!/bin/bash

# For conversion

rm *.crt *.pem *.cer

make

for i in *.cer; do
	cert=`echo "$i" | cut -d'.' -f1`

	{ # try

	openssl x509 -in "$cert.cer" -out "$cert.pem" -inform DER -outform PEM
    
    #save your output

	} || { # catch
		{ # try

			openssl x509 -in "$cert.cer" -out "$cert.pem" -inform PEM -outform PEM
		    

		} || { # catch
		    echo "something went wrong";
		}


	}

	echo "$cert"


done


for i in *.crt; do
	cert=`echo "$i" | cut -d'.' -f1`
	openssl x509 -in "$cert.crt" -out "$cert.pem" -inform DER -outform PEM
    if [[ $? -eq 1 ]]; then
		echo "$cert"
    fi
done

rm *.crt *.cer CC_KS

