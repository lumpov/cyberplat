#include <stdio.h>
#include "libipriv.h"
#ifdef _WIN32
#include <fcntl.h>
#include <sys\stat.h>
#include <io.h>
#include <process.h>
#endif
#include "i_stdlib.h"


int eng=IPRIV_ENGINE_RSAREF;

struct TEST_ITEM
{
	char name[32];
	int (*func) (void);
};


int test_genkeycard(void)
{
	int rc;
	if((rc=Crypt_GenKeyCardToFile("Kapi17032_gen.dat","api17032 test",17033))>0)
		rc=0;
	else if(!rc)
		rc=-1000;
	return rc;
}


int test_genkey512(void)
{
	int rc;

	IPRIV_KEY sec;
	IPRIV_KEY pub;

	rc=Crypt_GenKeyFromFile(eng,"Kapi17032_gen.dat",&sec,&pub,512);
	if(!rc)
	{
		if((rc=Crypt_ExportSecretKeyToFile("secret_512.key","1111111111",&sec))>0)
		{
			if((rc=Crypt_ExportPublicKeyToFile("public_512.key",&pub,&sec))>0)
				rc=0;
			else if(!rc)
				rc=-1000;
		}else if(!rc)
			rc=-1000;
		
		Crypt_CloseKey(&sec);
		Crypt_CloseKey(&pub);
	}
	return rc;
}
int test_genkey1024(void)
{
	int rc;

	IPRIV_KEY sec;
	IPRIV_KEY pub;

	rc=Crypt_GenKeyFromFile(eng,"Kapi17032_gen.dat",&sec,&pub,1024);
	if(!rc)
	{
		if((rc=Crypt_ExportSecretKeyToFile("secret_1024.key","1111111111",&sec))>0)
		{
			if((rc=Crypt_ExportPublicKeyToFile("public_1024.key",&pub,&sec))>0)
				rc=0;
			else if(!rc)
				rc=-1000;
		}else if(!rc)
			rc=-1000;
		Crypt_CloseKey(&sec);
		Crypt_CloseKey(&pub);
	}
	return rc;
}
int test_genkey2048(void)
{
	int rc;

	IPRIV_KEY sec;
	IPRIV_KEY pub;

	rc=Crypt_GenKeyFromFile(eng,"Kapi17032_gen.dat",&sec,&pub,2048);
	if(!rc)
	{
		if((rc=Crypt_ExportSecretKeyToFile("secret_2048.key","1111111111",&sec))>0)
		{
			if((rc=Crypt_ExportPublicKeyToFile("public_2048.key",&pub,&sec))>0)
				rc=0;
			else if(!rc)
				rc=-1000;
		}else if(!rc)
			rc=-1000;
		Crypt_CloseKey(&sec);
		Crypt_CloseKey(&pub);
	}
	return rc;
}

int test_sign_and_verify_512(void)
{
	int rc;
	IPRIV_KEY sec;
	IPRIV_KEY pub1;
	IPRIV_KEY pub2;
	char temp[1024];
	FILE* fp;

	rc=Crypt_OpenSecretKeyFromFile(eng,"secret_512.key","1111111111",&sec);
	if(!rc)
	{
		rc=Crypt_OpenPublicKeyFromFile(eng,"public_512.key",17033,&pub1,0);
		if(!rc)
		{
			rc=Crypt_OpenPublicKeyFromFile(eng,"public_512.key",17033,&pub2,&pub1);
			if(!rc)
			{
				
				rc=Crypt_Sign("Hello world",-1,temp,sizeof(temp),&sec);
				if(rc>0)
				{
					fp=fopen("msg_512.txt","wb");
					if(fp)
					{
						fwrite(temp,1,rc,fp);
						fclose(fp);
					}

					rc=Crypt_Verify(temp,rc,0,0,&pub2);
				}else if(!rc)
					rc=-1000;

				Crypt_CloseKey(&pub2);
			}
			Crypt_CloseKey(&pub1);
		}
		Crypt_CloseKey(&sec);
	}
	return rc;
}

int test_sign_and_verify_1024(void)
{
	int rc;
	IPRIV_KEY sec;
	IPRIV_KEY pub1;
	IPRIV_KEY pub2;
	char temp[1024];
	FILE* fp;

	rc=Crypt_OpenSecretKeyFromFile(eng,"secret_1024.key","1111111111",&sec);
	if(!rc)
	{
		rc=Crypt_OpenPublicKeyFromFile(eng,"public_1024.key",17033,&pub1,0);
		if(!rc)
		{
			rc=Crypt_OpenPublicKeyFromFile(eng,"public_1024.key",17033,&pub2,&pub1);
			if(!rc)
			{
				
				rc=Crypt_Sign("Hello world",-1,temp,sizeof(temp),&sec);
				if(rc>0)
				{
					fp=fopen("msg_1024.txt","wb");
					if(fp)
					{
						fwrite(temp,1,rc,fp);
						fclose(fp);
					}

					rc=Crypt_Verify(temp,rc,0,0,&pub2);
				}else if(!rc)
					rc=-1000;

				Crypt_CloseKey(&pub2);
			}
			Crypt_CloseKey(&pub1);
		}
		Crypt_CloseKey(&sec);
	}
	return rc;
}

int Crypt_FindPublicKey_1024(unsigned long keyserial,IPRIV_KEY* key,char* /*info*/,int /*info_len*/ )
{
	return Crypt_OpenPublicKeyFromFile(eng,"public_1024.key",keyserial, key, NULL);
}


int test_sign_and_verify2_1024(void)
{
	int rc;
	IPRIV_KEY sec;
	char temp[1024] = {0};

	rc=Crypt_OpenSecretKeyFromFile(eng,"secret_1024.key","1111111111",&sec);
	if(!rc)
	{
		rc=Crypt_Sign2("Hello world",-1,temp,sizeof(temp),&sec);
		if(rc>0)
		{
		        char temp2[4096];
		        int n=sprintf(temp2,"%s\r\n\r\nBEGIN SIGNATURE\r\n%s\r\nEND SIGNATURE\r\n","Hello world",temp);
			unsigned long kS = 0;
			rc = Crypt_Verify2(temp2,n,Crypt_FindPublicKey_1024,0,0,&kS);
		}else if(!rc)
			rc=-1000;

		Crypt_CloseKey(&sec);
	}
	return rc;
}

int test_sign_and_verify_2048(void)
{
	int rc;
	IPRIV_KEY sec;
	IPRIV_KEY pub1;
	IPRIV_KEY pub2;
	char temp[1024];
	FILE* fp;

	rc=Crypt_OpenSecretKeyFromFile(eng,"secret_2048.key","1111111111",&sec);
	if(!rc)
	{
		rc=Crypt_OpenPublicKeyFromFile(eng,"public_2048.key",17033,&pub1,0);
		if(!rc)
		{
			rc=Crypt_OpenPublicKeyFromFile(eng,"public_2048.key",17033,&pub2,&pub1);
			if(!rc)
			{
				
				rc=Crypt_Sign("Hello world",-1,temp,sizeof(temp),&sec);
				if(rc>0)
				{
					fp=fopen("msg_2048.txt","wb");
					if(fp)
					{
						fwrite(temp,1,rc,fp);
						fclose(fp);
					}

					rc=Crypt_Verify(temp,rc,0,0,&pub2);
				}else if(!rc)
					rc=-1000;

				Crypt_CloseKey(&pub2);
			}
			Crypt_CloseKey(&pub1);
		}
		Crypt_CloseKey(&sec);
	}
	return rc;
}

int test_import_export(void)
{
	int rc;
	IPRIV_KEY sec;
	IPRIV_KEY pub;

	rc=Crypt_OpenSecretKeyFromFile(eng,"secret.key","1111111111",&sec);
	if(!rc)
	{
		rc=Crypt_OpenPublicKeyFromFile(eng,"pubkeys.key",17033,&pub,0);
		if(!rc)
		{
			rc=Crypt_ExportSecretKeyToFile("secret_exp.key","1111111111",&sec);
			if(rc>0)
			{
				rc=Crypt_ExportPublicKeyToFile("pubkeys_exp.key",&pub,&sec);
				if(rc>0)
					rc=0;
				else if(!rc)
					rc=-1000;
			}else if(!rc)
				rc=-1000;
			Crypt_CloseKey(&pub);
		}
		Crypt_CloseKey(&sec);
	}
	
	
	if(!rc)
	{
		rc=Crypt_OpenSecretKeyFromFile(eng,"secret_exp.key","1111111111",&sec);
		if(!rc)
		{
			rc=Crypt_OpenPublicKeyFromFile(eng,"pubkeys_exp.key",17033,&pub,0);
			if(!rc)
				Crypt_CloseKey(&pub);
			Crypt_CloseKey(&sec);
		}
	}
	
	return rc;
}

#ifdef _WIN32
int test_extern_verify_512(void)
{
	return system("checker -c public_512.key < msg_512.txt > nul");
}
int test_extern_verify_1024(void)
{
	return system("checker -c public_1024.key < msg_1024.txt > nul");
}

int test_extern_sign_and_verify_512(void)
{
	int rc;
	FILE* fp;
	char temp[1024];
	
	rc=system("checker -s secret.key 1111111111 < message.txt > msg.txt");
	if(rc)
		return rc;
		
	IPRIV_KEY pub;
	rc=Crypt_OpenPublicKeyFromFile(eng,"pubkeys.key",17033,&pub,0);
	if(!rc)
	{
		fp=fopen("msg.txt","rb");
		if(fp)
		{
			rc=fread(temp,1,sizeof(temp),fp);
			fclose(fp);
		}
		if(rc>0)
			rc=Crypt_Verify(temp,rc,0,0,&pub);
		else
			rc=-1000;
		Crypt_CloseKey(&pub);
	}

	return rc;
}
#endif

int test_sign_and_verify_512_2(void)
{
	int rc;
	IPRIV_KEY sec;
	IPRIV_KEY pub1;
	char temp[1024];

	static const char sb[]=
	"lQEEAwAAQok95z4+AAABAgDrzoyI24MItz/UdYrV7as4xrjhjpYqBG3Owb7dP1pE\r\n"
	"p6Dz4MLJkdWzm+ccjy3pTmjgvqfnaAnRyID4nrwQ9+p9AAURATXU8D817k6vAfqv\r\n"
	"qaNX3nRlR6EMHSyDSoMzeMYZ64D5OgHqIt+rnqRLqApwk5tP5ewscxfr6coACuF5\r\n"
	"qLJAKmAtwHRZnY8cWgKzAQBMyV0nshDFbN7+biMSPGobWjhhQ8GlVfi1636/FZqe\r\n"
	"TQEApdjYa7cCBMKNdJojykQ977wVZpcYzDZ0zIWBRhfLez0BAPTvT/ipmFxcjtGG\r\n"
	"z0sFSYk7QVaXIoCIdugQbd4Z+iq8TPK0CGFwaTE3MDMy\r\n"
	"=Uxun\r\n";
	
	static const char b[]=
	"mQBRAwAAQok95z4+AAABAgDrzoyI24MItz/UdYrV7as4xrjhjpYqBG3Owb7dP1pE\r\n"
	"p6Dz4MLJkdWzm+ccjy3pTmjgvqfnaAnRyID4nrwQ9+p9AAURsAGHtAhhcGkxNzAz\r\n"
	"MrABAw==\r\n"
	"=5jFd";

	
//	rc=Crypt_OpenSecretKeyFromFile(eng,"secret.key","1111111111",&sec);
	rc=Crypt_OpenSecretKey2(eng,sb,sizeof(sb)-1,"1111111111",&sec);
	if(!rc)
	{
		rc=Crypt_OpenPublicKey2(eng,b,sizeof(b)-1,&pub1);

		if(!rc)
		{
			rc=Crypt_Sign("Hello world",-1,temp,sizeof(temp),&sec);
			if(rc>0)
			{
				rc=Crypt_Verify(temp,rc,0,0,&pub1);
			}else if(!rc)
				rc=-1000;
			Crypt_CloseKey(&pub1);
		}
		Crypt_CloseKey(&sec);
	}
	return rc;
}

int test_encrypt_decrypt_512(void)
{
	int rc;
	IPRIV_KEY sec;
	IPRIV_KEY pub;

	rc=Crypt_OpenSecretKeyFromFile(eng,"secret.key","1111111111",&sec);
	if(!rc)
	{
		rc=Crypt_OpenPublicKeyFromFile(eng,"pubkeys.key",17033,&pub,0);
		if(!rc)
		{
			char dst[1024];
			rc=Crypt_Encrypt("Hello world",-1,dst,sizeof(dst),&pub);
			if(rc>0)
			{
				printf(" \"%s\" ...",dst);
				
				rc=Crypt_Decrypt(dst,rc,dst,sizeof(dst),&sec);
				if(rc>0)
				{				
					printf(" \"%s\" ...",dst);
					rc=0;
				}
			}
			Crypt_CloseKey(&pub);
		}
		Crypt_CloseKey(&sec);
	}
	return rc;
}

int test_encrypt_decrypt_Long(void)
{
	int rc;
	IPRIV_KEY sec;
	IPRIV_KEY pub;

	rc=Crypt_OpenSecretKeyFromFile(eng,"secret.key","1111111111",&sec);
	if(!rc)
	{
		rc=Crypt_OpenPublicKeyFromFile(eng,"pubkeys.key",17033,&pub,0);
		if(!rc)
		{
			char dst[2048];
			rc=Crypt_EncryptLong("Hello world!",-1,dst,sizeof(dst),&pub);
			if(rc>0)
			{
				printf(" \"%s\" ...",dst);
				
				rc=Crypt_DecryptLong(dst,rc,dst,sizeof(dst),&sec);
				if(rc>0)
				{				
					printf(" \"%s\" ...",dst);
					rc=0;
				}
			}
			Crypt_CloseKey(&pub);
		}
		Crypt_CloseKey(&sec);
	}
	return rc;
}

int test_sign2_512(void)
{
	int rc;
	IPRIV_KEY sec;
	IPRIV_KEY pub;

	rc=Crypt_OpenSecretKeyFromFile(eng,"secret.key","1111111111",&sec);
	if(!rc)
	{
		rc=Crypt_OpenPublicKeyFromFile(eng,"pubkeys.key",17033,&pub,0);
		if(!rc)
		{
			char dst[1024];
			rc=Crypt_Sign2("Hello world",-1,dst,sizeof(dst),&sec);
			if(rc>0)
			{
				printf(" \"%s\" ...",dst);
				rc=Crypt_Verify3("Hello world",-1,dst,rc,&pub);
			}
			Crypt_CloseKey(&pub);
		}
		Crypt_CloseKey(&sec);
	}
	return rc;
}


TEST_ITEM tests_list[]=
{
	"KeyCard",test_genkeycard,
	"GenKey_512",test_genkey512,
	"SignAndVerify_512",test_sign_and_verify_512,
	"SignAndVerify_512_2",test_sign_and_verify_512_2,
	"GenKey_1024",test_genkey1024,
	"SignAndVerify_1024",test_sign_and_verify_1024,
	"SignAndVerify2_1024",test_sign_and_verify2_1024,
	"ExportImport",test_import_export,
#ifdef WITH_2048_KEYS
	"GenKey_2048",test_genkey2048,
	"SignAndVerify_2048",test_sign_and_verify_2048,
#endif
#ifdef _WIN32
	"ExternVerify_512",test_extern_verify_512,
	"ExternVerify_1024",test_extern_verify_1024,
	"ExternSignAndVerify_512",test_extern_sign_and_verify_512,
#endif
	"Encrypt_and_decrypt_512",test_encrypt_decrypt_512,
	"Encrypt_and_decrypt_Long",test_encrypt_decrypt_Long,
	"Sign2_512",test_sign2_512,
	0,0
};

int main(void)
{
	int rc;
	int i;
	int errors=0;

#ifdef _WIN32
	_setmode(1,O_BINARY);
	_setmode(2,O_BINARY);
#endif
	Crypt_Initialize();

        Crypt_SetHashAlg(IPRIV_ALG_MD5);
//        Crypt_SetHashAlg(IPRIV_ALG_SHA256);

	for(i=0;;i++)
	{
		if(!tests_list[i].func)
			break;
		printf("%s......................",tests_list[i].name);
		fflush(stdout);
		rc=tests_list[i].func();
		if(!rc)
			printf("OK\n");
		else
		{
			printf("FAIL (%i)\n",rc);
			errors++;
		}
		fflush(stdout);
	}
	
	Crypt_Done();

#ifdef __DEBUG
	rc=GetMemUsage();
	if(rc)
		printf("WARNING!!! MEMORY LEAK DETECTED: %i bytes\n",rc);
#endif

	printf("ERRORS: %i\n",errors);

	return errors;
}

