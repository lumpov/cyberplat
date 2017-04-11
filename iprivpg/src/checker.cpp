#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <stdlib.h>
#include <libipriv.h>
#include <errno.h>
#include <map>

enum { cm_help=0, cm_sign=1, cm_verify=2 };

static const char ERROR_HEADER[]="SessionStatus=1&Error=";

void my_perror(const char* err)
{
    fprintf(stdout,"%s%s: %s\n",ERROR_HEADER,err,strerror(errno));
}

std::string trim(const std::string& s)
{
    const char* p1=s.c_str();
    const char* p2=p1+s.length();

    while(*p1 && *p1==' ')
        p1++;

    while(p2>p1 && p2[-1]==' ')
        p2--;

    return std::string(p1,p2-p1);
}

int readfile(const char* infile,std::string& data)
{
    FILE* fp=stdin;

    if(infile && *infile)
    {
        fp=fopen(infile,"rb");

        if(!fp)
            { my_perror(infile); return -1; }
    }

    data.reserve(4096);

    char buf[1024];

    size_t n;

    while((n=fread(buf,1,sizeof(buf),fp))>0)
        data.append(buf,n);

    if(fp!=stdin)
        fclose(fp);

    return 0;
}

int doit(int cmd,const char* infile,const char* inifile);

int main(int argc,char** argv)
{
    int cmd=0;
    const char* infile=0;
    const char* inifile=0;

    int opt;
    while((opt=getopt(argc,argv,"h?csf:"))!=-1)
        switch(opt)
        {
        case 'h':
        case '?':
            break;
        case 'c':
            cmd=cm_verify;
            break;
        case 's':
            cmd=cm_sign;
            break;
        case 'f':
            inifile=optarg;
            break;
        }

    if(argc>optind)
        infile=argv[optind];

    if(cmd==cm_help)
        fprintf(stderr,"USAGE: ./checker -s|-c [-f inifile] [infile]\n");
    else
        return doit(cmd,infile?infile:"",inifile?inifile:"checker.ini");

    return 1;
}

int doit(int cmd,const char* infile,const char* inifile)
{
    std::string skeyfile;
    std::string pkeyfile;
    std::string passwd;
    int         bankkey=0;
    std::string data;

    {
        std::map<std::string,std::string> cfg;

        FILE* fp=fopen(inifile,"rb");

        if(!fp)
            { my_perror(inifile); return 1; }
        else
        {
            char buf[1024];

            while(fgets(buf,sizeof(buf),fp))
            {
                char* p=strpbrk(buf,";\r\n#");
                if(p)
                    *p=0;

                p=strchr(buf,'=');

                if(p)
                {
                    *p=0;
                    p++;

                    cfg[trim(buf)]=trim(p);
                }
            }

            fclose(fp);

            skeyfile=cfg["seckeyfile"];
            if(!skeyfile.length())
                skeyfile="secret.key";

            pkeyfile=cfg["pubkeyfile"];
            if(!pkeyfile.length())
                pkeyfile="pubkeys.key";

            skeyfile=cfg["keypath"]+skeyfile;
            pkeyfile=cfg["keypath"]+pkeyfile;
            passwd=cfg["password"];
            bankkey=atoi(cfg["bankkey"].c_str());
        }
    }

    if(readfile(infile,data))
        return 1;

    Crypt_Initialize();

    int eng=IPRIV_ENGINE_RSAREF;

    if(Crypt_Ctrl(IPRIV_ENGINE_OPENSSL,IPRIV_ENGCMD_IS_READY)>0)
        eng=IPRIV_ENGINE_OPENSSL;

    IPRIV_KEY key;
    
    int rc;

    if(cmd==cm_sign)
	rc=Crypt_OpenSecretKeyFromFile(eng,skeyfile.c_str(),passwd.c_str(),&key);
    else
	rc=Crypt_OpenPublicKeyFromFile(eng,pkeyfile.c_str(),bankkey,&key,0);

    if(rc)
    {
        if(cmd==cm_sign)
            fprintf(stdout,"%s%s: unable to load secret key (err=%i)\n",ERROR_HEADER,skeyfile.c_str(),rc);
        else
            fprintf(stdout,"%s%s: unable to load public key %i (err=%i)\n",ERROR_HEADER,pkeyfile.c_str(),bankkey,rc);

        Crypt_Done();
        return 1;
    }

    int retval=1;

    if(cmd==cm_sign)
    {
        int ndst=data.length()+512;

        char* dst=(char*)malloc(ndst);

        if(!dst)
            fprintf(stdout,"%smalloc: out of memory\n",ERROR_HEADER);
        else
        {
            rc=Crypt_Sign(data.c_str(),data.length(),dst,ndst,&key);

            if(rc>=0)
            {
                fwrite(dst,rc,1,stdout);
                fputc('\n',stdout);
                retval=0;
            }else
                fprintf(stdout,"%sCrypt_Sign: unable to create signature (err=%i)\n",ERROR_HEADER,rc);

            free(dst);
        }
    }else
    {
        const char* pp=0;
        int npp=0;

        rc=Crypt_Verify(data.c_str(),data.length(),&pp,&npp,&key);

	if(!rc)
	{
            fwrite(pp,npp,1,stdout);
            fputc('\n',stdout);
	    retval=0;
	}else
            fprintf(stdout,"%sCrypt_Verify: unable to verify signature (err=%i)\n",ERROR_HEADER,rc);
    }	

    Crypt_CloseKey(&key);    
    
    Crypt_Done();

    return retval;
}
