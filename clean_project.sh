pushd `dirname $0` > /dev/null
SCRIPTPATH=`pwd -P`
popd > /dev/null

echo "Cleaning" 

rm -rf $SCRIPTPATH/mboxes
rm -rf $SCRIPTPATH/receipts 
rm -rf $SCRIPTPATH/Server/mboxes/*
rm -rf $SCRIPTPATH/Server/receipts/*

#rm $SCRIPTPATH/Client/clients/*

echo "Done :)"

