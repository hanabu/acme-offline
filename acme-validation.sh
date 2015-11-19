#!/bin/sh

SERVER="$1"
TOKEN="$2"
TOKEN_FILE="$3"

echo
echo "================================================================"
echo
echo "(1) Copy token file to your web server." 
echo "    scp ${TOKEN_FILE} \\"
echo "        ${SERVER}:/DOC_ROOT/.well-known/acme-challenge" 
echo "(2) Then press enter key."

read line

exit 0
