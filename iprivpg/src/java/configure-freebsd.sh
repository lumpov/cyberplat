#!/bin/sh

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

if test -d "$JDK/include/freebsd"; then
echo -n '-I$(JDK)/include/freebsd ' >> $MAKEFILE
fi

if test -f "$JDK/jre/lib/i386/libjava.so"; then
echo -n '-L$(JDK)/jre/lib/i386 ' >> $MAKEFILE
echo -n '-Xlinker -rpath $(JDK)/jre/lib/i386' >> $MAKEFILE
fi

if test -f "$JDK/jre/lib/amd64/libjava.so"; then
echo -n '-L$(JDK)/jre/lib/amd64 ' >> $MAKEFILE
echo -n '-Xlinker -rpath $(JDK)/jre/lib/amd64' >> $MAKEFILE
fi

echo '' >> $MAKEFILE

echo 'JDK_LIBS=-ljava' >> $MAKEFILE

echo '' >> $MAKEFILE

if test -f utils/rules.posix; then
    cat utils/rules.posix >> $MAKEFILE
fi

cp utils/Makefile.freebsd Makefile