PHP_ARG_ENABLE(ipriv,
	[whether to enable "ipriv" support],
	[ --enable-ipriv   Enable "ipriv" support])

if test "$PHP_IPRIV" = "yes"; then
	PHP_REQUIRE_CXX()
	PHP_SUBST(IPRIV_SHARED_LIBADD)
	PHP_ADD_LIBRARY(stdc++, 1, IPRIV_SHARED_LIBADD)
	PHP_ADD_INCLUDE(../../..)

	AC_DEFINE(HAVE_IPRIV, 1, [Whether you have Ipriv])
	PHP_NEW_EXTENSION(ipriv, ipriv.c, $ext_shared)
fi
