#!/bin/sh

echo -n 'OPT_OPENSSL=' > config.mk
echo `./utils/chk_openssl.sh` >> config.mk