#!/bin/bash

MAKEFILE=rules.mk

gcc -fno-rtti -fno-exceptions -o ./jenv utils/jenv.cpp
javac -d ./ utils/jenv.java
JDK=`./jenv jdk`
rm -f jenv.class jenv


echo "JDK=$JDK" > $MAKEFILE

echo -n 'JDK_FLAGS=' >> $MAKEFILE

if test -f "$JDK/include/jni.h"; then
echo -n '-I$(JDK)/include ' >> $MAKEFILE
fi

if test -d "$JDK/include/linux"; then
echo -n '-I$(JDK)/include/linux ' >> $MAKEFILE
fi

if test -f "$JDK/jre/lib/i386/client/libjvm.so"; then
echo -n '-L$(JDK)/jre/lib/i386/client ' >> $MAKEFILE
echo -n '-Xlinker -rpath $(JDK)/jre/lib/i386/client' >> $MAKEFILE
fi

if test -f "$JDK/jre/lib/amd64/client/libjvm.so"; then
echo -n '-L$(JDK)/jre/lib/amd64/client ' >> $MAKEFILE
echo -n '-Xlinker -rpath $(JDK)/jre/lib/amd64/client' >> $MAKEFILE
fi

echo '' >> $MAKEFILE

echo 'JDK_LIBS=-ljvm' >> $MAKEFILE

echo '' >> $MAKEFILE

if test -f utils/rules.posix; then
    cat utils/rules.posix >> $MAKEFILE
fi

cp utils/Makefile.linux Makefile