
#include <string.h>

#include "wr_ipriv.h"
#include "getbuffer.h"

using namespace v8;

//---------------------------------------------------------------------------------------
void initialize(const Nan::FunctionCallbackInfo<v8::Value> & info)
{
	info.GetReturnValue().Set(Nan::New(Crypt_Initialize()));
}

//---------------------------------------------------------------------------------------
void done(const Nan::FunctionCallbackInfo<v8::Value> & info)
{
	info.GetReturnValue().Set(Nan::New(Crypt_Done()));
}

//---------------------------------------------------------------------------------------
Nan::Persistent<v8::Function> IprivKey::constructor;

//---------------------------------------------------------------------------------------
void IprivKey::Init(v8::Local<v8::Object> exports)
{
	// Constructor
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
	tpl->SetClassName(Nan::New("IprivKey").ToLocalChecked());
	tpl->InstanceTemplate()->SetInternalFieldCount(3);

	// Prototype
	Nan::SetPrototypeMethod(tpl, "OpenSecretKeyFromFile", OpenSecretKeyFromFile);
	Nan::SetPrototypeMethod(tpl, "OpenPublicKeyFromFile", OpenPublicKeyFromFile);
	Nan::SetPrototypeMethod(tpl, "Sign", Sign);
	Nan::SetPrototypeMethod(tpl, "Verify", Verify);

	constructor.Reset(tpl->GetFunction());
	exports->Set(Nan::New("IprivKey").ToLocalChecked(), tpl->GetFunction());
}

//---------------------------------------------------------------------------------------
void IprivKey::New(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
  if (info.IsConstructCall())
  {
    // Invoked as constructor: `new IprivKey(...)`
    IprivKey * obj = new IprivKey();
    obj->Wrap(info.This());
    info.GetReturnValue().Set(info.This());
  }
  else
  {
    // Invoked as plain function `MyObject(...)`, turn into construct call.
	  const int argc = 1;
	  v8::Local<v8::Value> argv[argc] = { info[0] };
    v8::Local<v8::Function> cons = Nan::New<v8::Function>(constructor);
    info.GetReturnValue().Set(cons->NewInstance(0, argv));
  }
}

//---------------------------------------------------------------------------------------
IprivKey::IprivKey() :
    eng(IPRIV_ENGINE_RSAREF), // Select crypto engine
    alg(IPRIV_ALG_MD5)        // Select crypto hash algorithm. Use IPRIV_ALG_SHA256 for better security.
{
    memset(&mSecretKey, 0, sizeof(mSecretKey));

  //  std::cerr << "this= " << this << "\n";
}

//---------------------------------------------------------------------------------------
IprivKey::~IprivKey()
{
    Crypt_CloseKey(&mSecretKey);

    while (mPublicKeys.size())
    {
    	std::map<unsigned long, IPRIV_KEY>::iterator it = mPublicKeys.begin();

    	Crypt_CloseKey(&it->second);
    	mPublicKeys.erase(it);
    }
}

//---------------------------------------------------------------------------------------
void IprivKey::OpenSecretKeyFromFile(const Nan::FunctionCallbackInfo<v8::Value> & info)
{
	IprivKey * key = ObjectWrap::Unwrap<IprivKey>(info.Holder());

    if (info.Length() < 2) {
    	Nan::ThrowTypeError("Wrong number of arguments");
    	return;
    }

    if (!info[0]->IsString() || !info[1]->IsString()) {
    	Nan::ThrowTypeError("Wrong arguments");
    	return;
    }

    std::string filePath = *v8::String::Utf8Value(info[0]->ToString());
    std::string password = *v8::String::Utf8Value(info[1]->ToString());

//    std::cerr << "file: " << filePath << "\npassword:" << password << std::endl << "key: " << key << "\n";

	int rc = Crypt_OpenSecretKeyFromFile(key->eng, filePath.c_str(), password.c_str(), &(key->mSecretKey));

    //	std::cerr << "open = " << rc << std::endl;
    // std::cerr << "file: " << filePath << "password:" << password << std::endl << "RC=" << rc << std::endl;

	info.GetReturnValue().Set(Nan::New(rc));
}

//---------------------------------------------------------------------------------------
int IprivKey::OpenPublicKeyFromFile(const std::string & aFileName, unsigned long aKeySerial)
{
    IPRIV_KEY pubKey;

	int rc = Crypt_OpenPublicKeyFromFile(eng, aFileName.c_str(), aKeySerial, &pubKey, 0);

	if (0 == rc) {
		mPublicKeys.insert(std::pair<unsigned long, IPRIV_KEY>(pubKey.keyserial, pubKey));
	}

    return rc;
}

//---------------------------------------------------------------------------------------
void IprivKey::OpenPublicKeyFromFile(const Nan::FunctionCallbackInfo<v8::Value> & info)
{
	IprivKey * key = ObjectWrap::Unwrap<IprivKey>(info.Holder());

    if (info.Length() < 2) {
    	Nan::ThrowTypeError("Wrong number of arguments");
    	return;
    }

    if (!info[0]->IsString()) {
    	Nan::ThrowTypeError("Wrong argument 0");
    	return;
    }

    key->mPublicKeyPath = *v8::String::Utf8Value(info[0]->ToString());
    uint32_t serial = info[1]->Uint32Value();

    if (serial == 0) {
    	Nan::ThrowTypeError("Wrong arguments 1");
    	return;
    }

    int rc = key->OpenPublicKeyFromFile(key->mPublicKeyPath, serial);

    //std::cerr << "openPublic = " << rc << std::endl;

	info.GetReturnValue().Set(Nan::New(rc));
}


//---------------------------------------------------------------------------------------
int Crypt_FindPublicKey_Func(unsigned long keyserial, IPRIV_KEY * key, char * /*info*/,int /*info_len*/ )
{
	return CRYPT_ERR_FILE_NOT_FOUND;
}

//---------------------------------------------------------------------------------------
void IprivKey::Verify(const Nan::FunctionCallbackInfo<v8::Value> & info)
{
	IprivKey * key = ObjectWrap::Unwrap<IprivKey>(info.Holder());

    if (info.Length() < 2) {
    	Nan::ThrowTypeError("Wrong number of arguments");
    	return;
    }

    GetBuffer in(info[0]);
    GetBuffer out(info[1]);

    if (!in.isValid() || !out.isValid()) {
		Nan::ThrowTypeError("Wrong type of arguments");
    	return;
    }

    unsigned long keySerial = 0;
    int rc = Crypt_Verify2(in.getPtr(), in.getLength(), Crypt_FindPublicKey_Func, 0, 0, &keySerial);

    IPRIV_KEY pubKey;
    if (key->mPublicKeys.find(keySerial) == key->mPublicKeys.end()) {
        rc = key->OpenPublicKeyFromFile(key->mPublicKeyPath, keySerial);
        if (rc) {
            std::cerr << "OpenPublicKeyFromFile result: " << rc << "\n";
            
            Nan::ThrowTypeError("OpenPublicKeyFromFile failed");
            return;
        }
    }
    
    pubKey = key->mPublicKeys[keySerial];

    int size = out.getLength();
    const char * outPtr = in.getPtr();
	rc = Crypt_Verify(in.getPtr(), in.getLength(), &outPtr, &size, &pubKey);

	if (rc < 0) {
		Nan::ThrowError("Crypt_Verify error");
		return;
	}
    else {
        memset(out.getPtr(), 0, out.getLength());
        memcpy(out.getPtr(), outPtr, size);
    }

	info.GetReturnValue().Set(Nan::New(size));
}

//---------------------------------------------------------------------------------------
void IprivKey::Sign(const Nan::FunctionCallbackInfo<v8::Value> & info)
{
	IprivKey * key = ObjectWrap::Unwrap<IprivKey>(info.Holder());

    if (info.Length() < 2) {
    	Nan::ThrowTypeError("Wrong number of arguments");
    	return;
    }

    GetBuffer in(info[0]);
    GetBuffer out(info[1]);

    if (!in.isValid() || !out.isValid()) {
		Nan::ThrowTypeError("Wrong type of arguments");
    	return;
    }

//	printf("\n\nIN BUFFER:\n%s\nIN BUFFER SIZE=%d\n", inBuffer, inBufferSize);

//	printf("OUT BUFFER SIZE=%d\n\n", outBufferSize);

	int rc = Crypt_SignEx(in.getPtr(), in.getLength(), out.getPtr(), out.getLength(), &key->mSecretKey, key->alg);

	if (rc < 0) {
		Nan::ThrowError("Crypt_SignEx error");
		return;
	}

	info.GetReturnValue().Set(Nan::New(rc));
}

//---------------------------------------------------------------------------------------
void Init(v8::Local<v8::Object> exports)
{
	exports->Set(Nan::New("initialize").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(initialize)->GetFunction());
	exports->Set(Nan::New("done").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(done)->GetFunction());

	IprivKey::Init(exports);
}

//---------------------------------------------------------------------------------------
NODE_MODULE(iprivpg, Init)

//---------------------------------------------------------------------------------------
