{
	"targets": [
		{
			"target_name": "iprivpg",
			"cflags": [
				"-O2",
				"-fno-stack-protector",
				"-fPIC"
			],
			"include_dirs": [
				"<!(node -e \"require('nan')\")",
				"iprivpg/src",
				"iprivpg/src/idea",
				"iprivpg/src/rsaref",
				"iprivpg/src/rfc6234",
				"iprivpg/src/md5"
		     ],
			 "defines": [
		          "WITH_RSAREF",
				  "WITH_RSAREF_GENKEY",
				  "WITH_2048_KEYS",
				  "WITH_EXCEPTIONS",
				  "IDEA32"
			],
			"sources": [
				"iprivpg/wrapper/ipriv.cxx",
				"iprivpg/src/libipriv.cpp",
				"iprivpg/src/ipriv.cpp",
				"iprivpg/src/armor.cpp",
				"iprivpg/src/eng_rsaref.cpp",
				"iprivpg/src/i_stdlib.cpp",
				"iprivpg/src/keycard.cpp",
				"iprivpg/src/memfile.cpp",
				"iprivpg/src/packet.cpp",
				"iprivpg/src/radix64.cpp",
				"iprivpg/src/idea/idea.c",
				"iprivpg/src/md5/md5c.c",
				"iprivpg/src/rfc6234/sha256.c",
				"iprivpg/src/rsaref/rsa.c",
				"iprivpg/src/rsaref/r_stdlib.c",
				"iprivpg/src/rsaref/r_random.c",
				"iprivpg/src/rsaref/r_keygen.c",
				"iprivpg/src/rsaref/prime.c", 
				"iprivpg/src/rsaref/nn.c",
				"iprivpg/src/rsaref/digit.c"
			]
		}
	]
}
