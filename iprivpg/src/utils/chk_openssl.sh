#!/bin/sh

if gcc -o utils/chk_openssl utils/chk_openssl.c -lssl 2>/dev/null; then

echo -n 'true'
rm -f utils/chk_openssl

else

echo -n 'false'

fi