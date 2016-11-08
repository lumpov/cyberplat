#include <stdio.h>
#include <getopt.h>
#include "libipriv.h"
#include <termios.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sys/ioctl.h>
#include <stdlib.h>

int main(int argc,char** argv)
{
    const char* key_path="";
    const char* data_path="";
    int sign=0;

    int opt;
    while((opt=getopt(argc,argv,"?hk:s"))>=0)
	switch(opt)
	{
	case '?':
	case 'h':
	    fprintf(stderr,"USAGE: ./verify [-s] -k key_file data_file\n");
	    return 0;
	case 'k':
	    key_path=optarg;
	    break;
	case 's':
	    sign++;
	    break;
	}

    if(optind<argc)
	data_path=argv[optind];

    if(!*data_path)
    {
	fprintf(stderr,"no data file\n");
	return 1;
    }
    if(!*key_path)
    {
	fprintf(stderr,"no key file\n");
	return 1;
    }

    char s[32000];
    int len=0;

    FILE* fp=fopen(data_path,"r");
    if(fp)
    {
	for(;;)
	{
	    int n=fread(s+len,1,sizeof(s)-len,fp);
	    if(!n)
		break;
	    len+=n;
	}	
	fclose(fp);
    }else
	perror(data_path);


    const char* pass=0;

    if(sign)
    {
	struct termio tstdin;
        ioctl(0,TCGETA,&tstdin);
        int c_lflag=tstdin.c_lflag;    
        tstdin.c_lflag&=~(ECHO);
        ioctl(0,TCSETA,&tstdin);
        tstdin.c_lflag=c_lflag;
        fprintf(stderr,"enter passphrase:\n");
        pass=readline(0);
	ioctl(0,TCSETA,&tstdin);

	if(!pass)
	{
	    fprintf(stderr,"no passphrase\n");
	    return 1;
	}
    }

    
    Crypt_Initialize();
    
    IPRIV_KEY key;
    
    int rc;

    if(sign)
	rc=Crypt_OpenSecretKeyFromFile(IPRIV_ENGINE_RSAREF,key_path,pass,&key);
    else
	rc=Crypt_OpenPublicKeyFromFile(IPRIV_ENGINE_RSAREF,key_path,0,&key,0);

    if(!rc)
    {
	if(sign)
	{
	    char dst[32000];
	    rc=Crypt_Sign(s,len,dst,sizeof(dst),&key);
	    if(rc>=0)
		printf("%s\n",dst);
	    else
		fprintf(stderr,"can`t sign: %i\n",rc);    
	}else
	{
	    rc=Crypt_Verify(s,len,0,0,&key);
	    if(!rc)
		printf("OK\n");
	    else
		fprintf(stderr,"can`t verify: %i\n",rc);    
	}	
    
	Crypt_CloseKey(&key);
    }else
	fprintf(stderr,"can`t open key: %i\n",rc);    
    
    
    Crypt_Done();

    if(pass)
	free((void*)pass);

    return 0;
}
