# cyberplat
node module for Cyberplat API

Компиляция libipriv.so

1. cd iprivpg/src
2. sudo ./configure.sh
3. make -f Makefile.linux
4. make -f Makefile.linux tests
5. make -f Makefile.linux shared


node.js

1. скопировать файл libipriv.so
2. /tests
3. npm install
4. ./node cyberplat.js
