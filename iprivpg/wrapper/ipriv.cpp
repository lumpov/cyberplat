
#include <string.h>

#include "ipriv.h"

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
    memset(&mKey, 0, sizeof(mKey));

    std::cerr << "this= " << this << "\n";
}

//---------------------------------------------------------------------------------------
IprivKey::~IprivKey()
{
    Crypt_CloseKey(&mKey);
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

    std::cerr << "file: " << filePath << "\npassword:" << password << std::endl
    		<< "key: " << key << "\n";

	int rc = Crypt_OpenSecretKeyFromFile(key->eng, filePath.c_str(), password.c_str(), &(key->mKey));

    //	std::cerr << "open = " << rc << std::endl;
    std::cerr << "file: " << filePath << "password:" << password << std::endl
    		<< "RC=" << rc << std::endl;

	info.GetReturnValue().Set(Nan::New(rc));
}

/*
//---------------------------------------------------------------------------------------
int IprivKey::Sign(nbind::Buffer message, nbind::Buffer result)
{
    const char * input = reinterpret_cast<const char *>(message.data());
    int inputSize = message.length();

    char * output = reinterpret_cast<char *>(result.data());
    int outputSize = result.length();

    //  std::cerr << "msg(" << std::string(input, inputSize) << ") size = " << inputSize << "\n " << "outSize = " << outputSize << "\n";

    int rc = Crypt_SignEx(input, inputSize, output, outputSize, &mKey, alg);
    if (rc > 0)
    {
        return rc;
    }

    result.commit();
    return rc;
}
*/

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
