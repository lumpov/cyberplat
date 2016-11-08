#include "jiprivpg.h"
#include "IPriv_native.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libipriv.h>

#ifndef _WIN32
#include <iconv.h>
#else
#include <malloc.h>
#endif /* _WIN32 */

thread_safe::jni_mutex_t thread_safe::jni_mutex;

namespace utils
{
    int eng=IPRIV_ENGINE_RSAREF;				// Engine type
    int initialized=0;

#ifndef _WIN32
    iconv_t utf2local=(iconv_t)-1;
    iconv_t local2utf=(iconv_t)-1;
#endif /* _WIN32 */


#ifdef _WIN32
    int ext_code_page=1251;
    
    void set_code_page(const char* cp)
    {
	if(!lstrcmpi(cp,"WINDOWS-1251"))
	    ext_code_page=1251;
        else if(!lstrcmpi(cp,"UTF8"))
            ext_code_page=CP_UTF8;
        else if(!lstrcmpi(cp,"KOI8-R"))
            ext_code_page=20866;
	else if(!lstrcmpi(cp,"CP866"))
	    ext_code_page=866;
        else
            ext_code_page=CP_ACP;
    }
#else
    char ext_code_page[64]="windows-1251";

    void set_code_page(const char* cp)
    {
	if(!strncasecmp(cp,"UTF",3) && strstr(cp,"16"))
	    return;

	int n=snprintf(ext_code_page,sizeof(ext_code_page),"%s",cp);
	if(n<0 || n>=sizeof(ext_code_page))
	    ext_code_page[sizeof(ext_code_page)-1]=0;
	
	if(utf2local!=(void*)-1)
	    iconv_close(utf2local);
	if(local2utf!=(void*)-1)
	    iconv_close(local2utf);

#ifdef IS_BIGENDIAN
    utf2local=iconv_open(ext_code_page,"UTF-16BE");
    local2utf=iconv_open("UTF-16BE",ext_code_page);
#else
    utf2local=iconv_open(ext_code_page,"UTF-16LE");
    local2utf=iconv_open("UTF-16LE",ext_code_page);
#endif
    }
#endif /* _WIN32 */


#ifndef _WIN32
    const char* get_lang(void)
    {
	const char* lang=getenv("LANG");
	if(lang)
	{
	    static const char ru_RU[]="ru_RU";
	    if(!strncmp(lang,ru_RU,sizeof(ru_RU)-1))
		return "ru";
	}
	return "en";
    }
#else
    const char* get_lang(void)
    {
	LCID lcid=GetUserDefaultLCID();
	WORD langID=LANGIDFROMLCID(lcid);
	if(langID==0x0419)
	    return "ru";
	return "en";
    }
#endif /* _WIN32 */


    void throw_new(JNIEnv* env,int c)
    {
	jclass e_cls=env->FindClass("org/CyberPlat/IPrivException");
	if(e_cls)
	{
	    jthrowable e=(jthrowable)env->NewObject(e_cls,env->GetMethodID(e_cls,"<init>","(I)V"),(jint)c);	
//	    env->DeleteLocalRef(e_cls);
	    
	    if(e)
		env->Throw(e);
	}
    }


#ifndef _WIN32
    int convert_utf2local(const jchar* src,int src_len,char* dst,int dst_len)
    {
	if(utf2local==(iconv_t)-1)
	    return 0;

#if defined(_FREEBSD) || defined(__sun)
	const char* from=(char*)src;
#else
	char* from=(char*)src;
#endif

	size_t from_len=src_len*sizeof(jchar);
    
	char* to=dst;
	size_t to_len=dst_len;

	size_t rc=::iconv(utf2local, &from, &from_len, &to, &to_len);
	::iconv(utf2local,0,0,0,0);
    
	if(rc!=(size_t)-1)
	    return dst_len-to_len;
    
	return 0;
    }

    int get_string(JNIEnv* env,jstring s,char* dst,int dst_len)
    {
	int rc=0;

	const jchar* ptr=env->GetStringChars(s,0);

	if(ptr)
	{
	    rc=convert_utf2local(ptr,env->GetStringLength(s),dst,dst_len-1);

    	    env->ReleaseStringChars(s,ptr);
	}
	dst[rc]=0;
	return rc;
    }
#else
    int get_string(JNIEnv* env,jstring s,char* dst,int dst_len)
    {
	int rc=0;

        const jchar* ptr=env->GetStringChars(s,0);
        int len=env->GetStringLength(s);
        if(ptr)
	{
    	    rc=WideCharToMultiByte(ext_code_page,0,(WCHAR*)ptr,len,dst,dst_len-1,0,0);
    	    if(rc<0)
                rc=0;
            env->ReleaseStringChars(s,ptr);
	}
    	dst[rc]=0;
		return rc;
    }
#endif /* _WIN32 */

#ifndef _WIN32
    int convert_local2utf(const char* src,int src_len,jchar* dst,int dst_len)
    {
	if(local2utf==(iconv_t)-1)
	    return 0;

#if defined(_FREEBSD) || defined(__sun)
	const char* from=(char*)src;
#else
	char* from=(char*)src;
#endif

	size_t from_len=src_len;
    
	char* to=(char*)dst;
	size_t to_len=dst_len*sizeof(jchar);

	size_t rc=::iconv(local2utf, &from, &from_len, &to, &to_len);
	::iconv(local2utf,0,0,0,0);
    
	if(rc!=(size_t)-1)
	    return dst_len-(to_len/2);
    
	return 0;
    }
    jstring new_string(JNIEnv* env,const char* src,int src_len)
    {
	int dst_len=src_len+1;
	jchar* dst=(jchar*)malloc(dst_len*sizeof(jchar));
	if(!dst)
	    return 0;
	
	int n=convert_local2utf(src,src_len,dst,dst_len-1);
	dst[n]=0;
	
	jstring retval=env->NewString(dst,n);
		
	free(dst);
	
	return retval;
    }
#else
    jstring new_string(JNIEnv* env,const char* src,int src_len)
    {
	WCHAR* dst=(WCHAR*)malloc((src_len+1)*sizeof(WCHAR));
	if(!dst)
	    return 0;

	int rc=MultiByteToWideChar(ext_code_page,0,src,src_len,dst,src_len);
        if(rc<0)
	    rc=0;
	dst[rc]=0;
	
	jstring retval=env->NewString((const jchar*)dst,rc);
	    
	free(dst);
	
	return retval;
    }
#endif /* _WIN32 */
}

namespace keys
{
    IPRIV_KEY list[max_keys_num];

    void init(void)
    {
	for(int i=0;i<max_keys_num;i++)
	    list[i].type=0;
    }
    void done(void)
    {
	for(int i=0;i<max_keys_num;i++)
	    if(list[i].type)
		Crypt_CloseKey(list+i);
    }
    
    int find(void)
    {
	for(int i=0;i<max_keys_num;i++)
	    if(!list[i].type)
		return i;
	return -1;	
    }
    
    IPRIV_KEY* get(int n)
    {
	if(n<0 || n>=max_keys_num)
	    return 0;
	return list+n;
    }
}


#if __APPLE__ & __MACH__
extern "C" void _init(void) __attribute__ ((constructor));
extern "C" void _fini(void) __attribute__ ((destructor));
#endif

extern "C" void _init(void)
{
        if(utils::initialized)
            return;

	thread_model::init();
	keys::init();
	Crypt_Initialize();
	utils::set_code_page("windows-1251");
	if(Crypt_Ctrl(IPRIV_ENGINE_OPENSSL,IPRIV_ENGCMD_IS_READY)>0)
	    utils::eng=IPRIV_ENGINE_OPENSSL;

        utils::initialized=1;
}

extern "C" void _fini(void)
{
        if(!utils::initialized)
            return;

	keys::done();
	Crypt_Done();
	thread_model::done();
#ifndef _WIN32
	iconv_close(utils::utf2local);
	iconv_close(utils::local2utf);
#endif /* _WIN32 */

        utils::initialized=0;
}

#ifdef _WIN32
BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved)
{
	switch(fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		_init();
		break;
	case DLL_PROCESS_DETACH:
		_fini();
		break;
	}
	return TRUE;
}
#endif /* _WIN32 */










JNIEXPORT jstring JNICALL Java_org_CyberPlat_IPriv_1native_getLang                                                            
  (JNIEnv* env, jclass)
{
    jstring s=env->NewStringUTF(utils::get_lang());
    
    return s;
}

JNIEXPORT void JNICALL Java_org_CyberPlat_IPriv_1native_setCodePage_1native
  (JNIEnv* env, jclass, jstring s)
{
    const char* p=env->GetStringUTFChars(s,0);

    if(p)
    {
	thread_model::enter();
	utils::set_code_page(p);
	thread_model::leave();
        env->ReleaseStringUTFChars(s,p);
    }

//    env->DeleteLocalRef(s);
}

JNIEXPORT jint JNICALL Java_org_CyberPlat_IPriv_1native_openSecretKey_1native
  (JNIEnv* env, jclass, jstring path, jstring passwd)
{
    int rc=-70;

    thread_model::enter();

    int n=keys::find();
    if(n>=0)
    {
	char _path[1024];
	char _passwd[64];

	utils::get_string(env,path,_path,sizeof(_path));
	utils::get_string(env,passwd,_passwd,sizeof(_passwd));
	rc=Crypt_OpenSecretKeyFromFile(utils::eng,_path,_passwd,keys::list+n);
	
	memset(_passwd,0,sizeof(_passwd));
    }

//    env->DeleteLocalRef(path);
//    env->DeleteLocalRef(passwd);

    thread_model::leave();
    
    if(rc<0)
	utils::throw_new(env,rc);

    return n;
}

JNIEXPORT jint JNICALL Java_org_CyberPlat_IPriv_1native_openSecretKeyMem_1native
  (JNIEnv* env, jclass, jstring key, jstring passwd)
{
    int rc=-70;

    thread_model::enter();

    int n=keys::find();
    if(n>=0)
    {
	char _key[4096];
	char _passwd[64];

	utils::get_string(env,key,_key,sizeof(_key));
	utils::get_string(env,passwd,_passwd,sizeof(_passwd));
	rc=Crypt_OpenSecretKey(utils::eng,_key,-1,_passwd,keys::list+n);
	
	memset(_passwd,0,sizeof(_passwd));
    }

//    env->DeleteLocalRef(path);
//    env->DeleteLocalRef(passwd);

    thread_model::leave();
    
    if(rc<0)
	utils::throw_new(env,rc);

    return n;
}

JNIEXPORT jint JNICALL Java_org_CyberPlat_IPriv_1native_openPublicKey_1native
  (JNIEnv* env, jclass, jstring path, jint keyserial)
{
    int rc=-70;

    thread_model::enter();

    int n=keys::find();
    if(n>=0)
    {
	char _path[1024];

	utils::get_string(env,path,_path,sizeof(_path));

	rc=Crypt_OpenPublicKeyFromFile(utils::eng,_path,keyserial,keys::list+n,0);
    }

//    env->DeleteLocalRef(path);

    thread_model::leave();

    if(rc<0)
	utils::throw_new(env,rc);

    return n;
}

JNIEXPORT jint JNICALL Java_org_CyberPlat_IPriv_1native_openPublicKeyMem_1native
  (JNIEnv* env, jclass, jstring key, jint keyserial)
{
    int rc=-70;

    thread_model::enter();

    int n=keys::find();
    if(n>=0)
    {
	char _key[4096];

	utils::get_string(env,key,_key,sizeof(_key));

	rc=Crypt_OpenPublicKey(utils::eng,_key,-1,keyserial,keys::list+n,0);
    }

//    env->DeleteLocalRef(path);

    thread_model::leave();

    if(rc<0)
	utils::throw_new(env,rc);

    return n;
}

JNIEXPORT jstring JNICALL Java_org_CyberPlat_IPriv_1native_signText_1native
  (JNIEnv* env, jclass, jint keyid, jstring text)
{
    jstring retval=0;

    thread_model::enter();

    IPRIV_KEY* key=keys::get(keyid);
    if(!key)
	utils::throw_new(env,-72);
    else
    {
	int src_len=env->GetStringLength(text)*2+1;
	char* src=(char*)malloc(src_len);
    
	if(!src)
	    utils::throw_new(env,-71);
	else
	{
	    int dst_len=src_len+512;
	    char* dst=(char*)malloc(dst_len);
	
	    if(!dst)
		utils::throw_new(env,-71);
	    else
	    {
		src_len=utils::get_string(env,text,src,src_len);
		int rc=Crypt_Sign(src,src_len,dst,dst_len,key);
		if(rc<0)
		    utils::throw_new(env,rc);
		else
		{
		    retval=utils::new_string(env,dst,rc);
		    if(!retval)
			utils::throw_new(env,-71);
		}
		free(dst);
	    }
	    free(src);
	}
    }
    thread_model::leave();

//    env->DeleteLocalRef(text);
    
    return retval;
}

JNIEXPORT jstring JNICALL Java_org_CyberPlat_IPriv_1native_verifyText_1native
  (JNIEnv* env, jclass, jint keyid, jstring text)
{
    jstring retval=0;

    thread_model::enter();

    IPRIV_KEY* key=keys::get(keyid);
    if(!key)
	utils::throw_new(env,-72);
    else
    {
	int src_len=env->GetStringLength(text)*2+1;
	char* src=(char*)malloc(src_len);
    
	if(!src)
	    utils::throw_new(env,-71);
	else
	{
	    src_len=utils::get_string(env,text,src,src_len);
	    const char* dst=0;
	    int dst_len=0;

	    int rc=Crypt_Verify(src,src_len,&dst,&dst_len,key);
	    if(rc<0)
		utils::throw_new(env,rc);
	    else
	    {
		retval=utils::new_string(env,dst,dst_len);
		if(!retval)
		    utils::throw_new(env,-71);
	    }
	    free(src);
	}
    }
    thread_model::leave();

//    env->DeleteLocalRef(text);
    
    return retval;
}

JNIEXPORT jstring JNICALL Java_org_CyberPlat_IPriv_1native_signText2_1native
	(JNIEnv* env, jclass, jint keyid, jstring text)
{
	jstring retval=0;

	thread_model::enter();

	IPRIV_KEY* key=keys::get(keyid);
	if(!key)
		utils::throw_new(env,-72);
	else
	{
		int src_len=env->GetStringLength(text)*2+1;
		char* src=(char*)malloc(src_len);

		if(!src)
			utils::throw_new(env,-71);
		else
		{
			int dst_len=src_len+512;
			char* dst=(char*)malloc(dst_len);

			if(!dst)
				utils::throw_new(env,-71);
			else
			{
				src_len=utils::get_string(env,text,src,src_len);
				int rc=Crypt_Sign2(src,src_len,dst,dst_len,key);
				if(rc<0)
					utils::throw_new(env,rc);
				else
				{
					retval=utils::new_string(env,dst,rc);
					if(!retval)
						utils::throw_new(env,-71);
				}
				free(dst);
			}
			free(src);
		}
	}
	thread_model::leave();

	//    env->DeleteLocalRef(text);

	return retval;
}

JNIEXPORT jstring JNICALL Java_org_CyberPlat_IPriv_1native_verifyText2_1native
	(JNIEnv* env, jclass, jint keyid, jstring text, jstring sign)
{
	jstring retval=0;

	thread_model::enter();

	IPRIV_KEY* key=keys::get(keyid);
	if(!key)
		utils::throw_new(env,-72);
	else
	{
		int src_len=env->GetStringLength(text)*2+1;
		char* src=(char*)malloc(src_len);

		int sign_len=env->GetStringLength(sign)*2+1;
		char* sign_ptr=(char*)malloc(sign_len);

		if(!src)
			utils::throw_new(env,-71);
		else
		{
			src_len=utils::get_string(env,text,src,src_len);
			sign_len=utils::get_string(env,sign,sign_ptr,sign_len);
			
			int rc = Crypt_Verify3(src,src_len,sign_ptr,sign_len,key);
			if(rc<0)
				utils::throw_new(env,rc);
			else
			{
				retval = utils::new_string(env,"0",1);
				if(!retval)
					utils::throw_new(env,-71);
			}
			free(src);
			free(sign_ptr);
		}
	}
	thread_model::leave();

	//    env->DeleteLocalRef(text);

	return retval;
}

JNIEXPORT jstring JNICALL Java_org_CyberPlat_IPriv_1native_encryptText_1native
  (JNIEnv* env, jclass, jint keyid, jstring text)
{
    jstring retval=0;

    thread_model::enter();

    IPRIV_KEY* key=keys::get(keyid);
    if(!key)
	utils::throw_new(env,-72);
    else
    {
	char src[2048];
	int src_len=utils::get_string(env,text,src,sizeof(src));

	char dst[4096];
	int dst_len=Crypt_Encrypt(src,src_len,dst,sizeof(dst),key);
	if(dst_len<0)
	    utils::throw_new(env,dst_len);
	else
	{
	    retval=utils::new_string(env,dst,dst_len);
	    if(!retval)
		utils::throw_new(env,-71);
	}
    }
    thread_model::leave();

//    env->DeleteLocalRef(text);
    
    return retval;
}

JNIEXPORT jstring JNICALL Java_org_CyberPlat_IPriv_1native_decryptText_1native
  (JNIEnv* env, jclass, jint keyid, jstring text)
{
    jstring retval=0;

    thread_model::enter();

    IPRIV_KEY* key=keys::get(keyid);
    if(!key)
	utils::throw_new(env,-72);
    else
    {
	char src[4096];
	int src_len=utils::get_string(env,text,src,sizeof(src));

	char dst[2048];
	int dst_len=Crypt_Decrypt(src,src_len,dst,sizeof(dst),key);
	if(dst_len<0)
	    utils::throw_new(env,dst_len);
	else
	{
	    retval=utils::new_string(env,dst,dst_len);
	    if(!retval)
		utils::throw_new(env,-71);
	}
    }
    thread_model::leave();

//    env->DeleteLocalRef(text);
    
    return retval;
}

JNIEXPORT jint JNICALL Java_org_CyberPlat_IPriv_1native_closeKey_1native
  (JNIEnv* env, jclass, jint keyid)
{
    thread_model::enter();

    IPRIV_KEY* k=keys::get(keyid);
    if(k)
	Crypt_CloseKey(k);

    thread_model::leave();
	return 0;
}


JNIEXPORT jint JNICALL Java_org_CyberPlat_IPriv_1native_genKey_1native
  (JNIEnv* env, jclass, jstring _keycard, jint bits, jstring _passwd, jstring _sec, jstring _pub)
{
    char keycard[256];
    char passwd[256];
    char sec[256];
    char pub[256];

    utils::get_string(env,_keycard,keycard,sizeof(keycard));
    utils::get_string(env,_passwd,passwd,sizeof(passwd));
    utils::get_string(env,_sec,sec,sizeof(sec));
    utils::get_string(env,_pub,pub,sizeof(pub));

    IPRIV_KEY skey;
    IPRIV_KEY pkey;

    int rc=Crypt_GenKeyFromFile(utils::eng,keycard,&skey,&pkey,bits);

    if(rc)
        utils::throw_new(env,-73);

    Crypt_ExportSecretKeyToFile(sec,passwd,&skey);
    Crypt_ExportPublicKeyToFile(pub,&pkey,&skey);

    Crypt_CloseKey(&skey);
    Crypt_CloseKey(&pkey);

    return 0;
}

JNIEXPORT jobjectArray JNICALL Java_org_CyberPlat_IPriv_1native_genKeyMem_1native
  (JNIEnv* env, jclass, jstring _userid, jlong _keyserial, jint _bits, jstring _passwd)
{
    char userid[64];
    char passwd[64];

    utils::get_string(env,_userid,userid,sizeof(userid));
    utils::get_string(env,_passwd,passwd,sizeof(passwd));

    IPRIV_KEY sec;
    IPRIV_KEY pub;

    int rc=Crypt_GenKey2(utils::eng,_keyserial,userid,&sec,&pub,_bits);

    if(rc)
        utils::throw_new(env,-73);

    jobjectArray ret =(jobjectArray)env->NewObjectArray(2,env->FindClass("java/lang/String"),env->NewStringUTF(""));

    char tmp[4096];

    rc=Crypt_ExportSecretKey(tmp,sizeof(tmp),passwd,&sec);
    if(rc>0)
        env->SetObjectArrayElement(ret,0,env->NewStringUTF(tmp));

    rc=Crypt_ExportPublicKey(tmp,sizeof(tmp),&pub,&sec);
    if(rc>0)
        env->SetObjectArrayElement(ret,1,env->NewStringUTF(tmp));

    Crypt_CloseKey(&sec);
    Crypt_CloseKey(&pub);

    return ret;
}

JNIEXPORT void JNICALL Java_org_CyberPlat_IPriv_1native_initialize_1native
  (JNIEnv *, jclass)
{
    _init();
}

JNIEXPORT void JNICALL Java_org_CyberPlat_IPriv_1native_done_1native
  (JNIEnv *, jclass)
{
    _fini();
}

JNIEXPORT jbyteArray JNICALL Java_org_CyberPlat_IPriv_1native_signArray_1native
  (JNIEnv* env, jclass, jint keyid, jbyteArray text)
{
    int rc=0;

    jbyteArray retval=NULL;

    thread_model::enter();

    IPRIV_KEY* key=keys::get(keyid);
    if(!key)
        rc=-72;
    else
    {
	int src_len=env->GetArrayLength(text);
	char* src=(char*)env->GetByteArrayElements(text,0);
    
	if(!src)
	    rc=-71;
	else
	{
	    int dst_len=src_len+512;
	    char* dst=(char*)malloc(dst_len);
	
	    if(!dst)
	        rc=-71;
            else
	    {
		rc=Crypt_Sign(src,src_len,dst,dst_len,key);
		if(rc>=0)
		{
                    retval=env->NewByteArray(rc);
		    if(!retval)
		        rc=-71;
		    else
                        env->SetByteArrayRegion(retval,0,rc,(jbyte*)dst);
		}
		free(dst);
	    }
            env->ReleaseByteArrayElements(text,(jbyte*)src,0);
	}
    }
    thread_model::leave();

    if(rc<0)
        utils::throw_new(env,rc);

    return retval;
}

JNIEXPORT jbyteArray JNICALL Java_org_CyberPlat_IPriv_1native_verifyArray_1native
  (JNIEnv* env, jclass, jint keyid, jbyteArray text)
{
    int rc=0;

    jbyteArray retval=0;

    thread_model::enter();

    IPRIV_KEY* key=keys::get(keyid);
    if(!key)
        rc=-72;
    else
    {
	int src_len=env->GetArrayLength(text);
	char* src=(char*)env->GetByteArrayElements(text,0);
    
	if(!src)
	    rc=-71;
	else
	{
	    const char* dst=0;
	    int dst_len=0;

	    rc=Crypt_Verify(src,src_len,&dst,&dst_len,key);
	    if(rc>=0)
	    {
                retval=env->NewByteArray(dst_len);
                if(!retval)
	            rc=-71;
		else
                    env->SetByteArrayRegion(retval,0,dst_len,(jbyte*)dst);
	    }
            env->ReleaseByteArrayElements(text,(jbyte*)src,0);
	}
    }
    thread_model::leave();

    if(rc<0)
        utils::throw_new(env,rc);

    return retval;
}
