pushd `dirname $0` > /dev/null
SCRIPTPATH=`pwd -P`
popd > /dev/null

echo "Cleaning $SCRIPTPATH" 

rm -rf $SCRIPTPATH/mboxes
rm -rf $SCRIPTPATH/receipts 
rm -rf $SCRIPTPATH/Server/mboxes/*
rm -rf $SCRIPTPATH/Server/receipts/*
find $SCRIPTPATH -name "*.pyc" -type f -delete

#rm $SCRIPTPATH/Client/clients/*

echo "Done :)"

