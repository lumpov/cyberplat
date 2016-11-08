#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include "libipriv.h"

int main(int argc,char** argv)
{
    const char* card_path="";
    const char* sfile_path="";
    const char* pfile_path="";
    const char* passphrase="";
    int bits=0;

    int opt;
    while((opt=getopt(argc,argv,"?hk:s:p:b:"))>=0)
	switch(opt)
	{
	case '?':
	case 'h':
	    fprintf(stderr,"USAGE: ./genkey [-b bits] [-s secret_file] [-k passphrase] [-p public_file] card_file\n");
	    return 0;
	case 's':
	    sfile_path=optarg;
	    break;
	case 'p':
	    pfile_path=optarg;
	    break;
	case 'k':
	    passphrase=optarg;
	    break;
	case 'b':
	    bits=atoi(optarg);
	    break;
	}

    if(optind<argc)
	card_path=argv[optind];

    if(!*sfile_path)
	sfile_path="secret.key";
    if(!*pfile_path)
	pfile_path="pubkeys.key";
    if(!*passphrase)
	passphrase="1111111111";
    if(bits<=0)
	bits=512;
	
    if(!*card_path)
    {
	fprintf(stderr,"no key card file\n");
	return 1;
    }

    
    Crypt_Initialize();
    
    IPRIV_KEY skey;
    IPRIV_KEY pkey;
    
    int rc=Crypt_GenKeyFromFile(IPRIV_ENGINE_RSAREF,card_path,&skey,&pkey,bits);

    if(rc)
    {
	fprintf(stderr,"genkey fail: %i\n",rc);    
	Crypt_Done();
	return 1;
    }

    Crypt_ExportSecretKeyToFile(sfile_path,passphrase,&skey);
    Crypt_ExportPublicKeyToFile(pfile_path,&pkey,&skey);

    Crypt_CloseKey(&skey);
    Crypt_CloseKey(&pkey);

    
    Crypt_Done();

    return 0;
}
