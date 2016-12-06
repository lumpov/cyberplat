# cyberplat
node module for Cyberplat API

Компиляция libipriv.so

1. cd iprivpg/src
2. iprivpg/src/utils/chk_openssl.sh должен быть исполняемый
3. sudo ./configure.sh
4. make -f Makefile.linux
5. make -f Makefile.linux tests
6. make -f Makefile.linux shared


node.js

1. скопировать файл libipriv.so
2. /tests
3. npm install
4. ./node cyberplat.js
