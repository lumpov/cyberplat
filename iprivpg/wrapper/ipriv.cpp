
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
	Nan::SetPrototypeMethod(tpl, "Sign", Sign);

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

  //  std::cerr << "this= " << this << "\n";
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

//    std::cerr << "file: " << filePath << "\npassword:" << password << std::endl << "key: " << key << "\n";

	int rc = Crypt_OpenSecretKeyFromFile(key->eng, filePath.c_str(), password.c_str(), &(key->mKey));

    //	std::cerr << "open = " << rc << std::endl;
    // std::cerr << "file: " << filePath << "password:" << password << std::endl << "RC=" << rc << std::endl;

	info.GetReturnValue().Set(Nan::New(rc));
}

//---------------------------------------------------------------------------------------
void IprivKey::Sign(const Nan::FunctionCallbackInfo<v8::Value> & info)
{
	IprivKey * key = ObjectWrap::Unwrap<IprivKey>(info.Holder());

    if (info.Length() < 2) {
    	Nan::ThrowTypeError("Wrong number of arguments");
    	return;
    }

    if (!info[0]->IsUint8Array() || !info[1]->IsUint8Array()) {
    	Nan::ThrowTypeError("Wrong arguments");
    	return;
    }

    Uint8Array * in = Uint8Array::Cast(*info[0]->ToObject());
    Uint8Array * out = Uint8Array::Cast(*info[1]->ToObject());

    if (in == nullptr || out == nullptr)
    {
    	Nan::ThrowTypeError("Wrong arguments");
    	return;
    }

	if (!in->HasBuffer() || !out->HasBuffer())
	{
		Nan::ThrowError("Uint8Array Content error");
		return;
	}

	const char * inBuffer = (const char *)in->Buffer()->GetContents().Data() + in->ByteOffset();
	int inBufferSize = in->ByteLength();

	char * outBuffer = (char *)out->Buffer()->GetContents().Data() + out->ByteOffset();
	int outBufferSize = out->ByteLength();

//	printf("\n\nIN BUFFER:\n%s\nIN BUFFER SIZE=%d\n", inBuffer, inBufferSize);

//	printf("OUT BUFFER SIZE=%d\n\n", outBufferSize);

	int rc = Crypt_SignEx(inBuffer, inBufferSize, outBuffer, outBufferSize, &key->mKey, key->alg);

	if (rc < 0)
	{
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
