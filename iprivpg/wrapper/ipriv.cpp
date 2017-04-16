
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
	Nan::SetPrototypeMethod(tpl, "OpenPublicKeyFromFile", OpenPublicKeyFromFile);

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

    std::string filePath = *v8::String::Utf8Value(info[0]->ToString());
    uint32_t serial = info[1]->Uint32Value();

    if (serial == 0) {
    	Nan::ThrowTypeError("Wrong arguments 1");
    	return;
    }

//    std::cerr << "file: " << filePath << "\npassword:" << password << std::endl << "key: " << key << "\n";

	int rc = Crypt_OpenPublicKeyFromFile(key->eng, filePath.c_str(), serial, &(key->mKey), nullptr);

    std::cerr << "openPublic = " << rc << std::endl;
    // std::cerr << "file: " << filePath << "password:" << password << std::endl << "RC=" << rc << std::endl;

	info.GetReturnValue().Set(Nan::New(rc));
}
//---------------------------------------------------------------------------------------
class GetBuffer
{
	const v8::Local<Value> & mValue;
	char * mBuffer;
	int mLength;

	v8::String::Utf8Value * mStringValue;

public:
	//---------------------------------------------------------------------------------------
	explicit GetBuffer(const v8::Local<Value> & aValue) :
		mValue(aValue), mBuffer(nullptr), mLength(0), mStringValue(nullptr)
	{
//	    std::string inType = *v8::String::Utf8Value(aValue->ToObject()->ObjectProtoToString());
//	    printf("in object type: %s\n", inType.c_str());

		if (aValue->IsUint8Array())
		{
		    Uint8Array * in = Uint8Array::Cast(*aValue);

		    if (in->HasBuffer())
			{
		    	mBuffer = (char *)in->Buffer()->GetContents().Data() + in->ByteOffset();
		    	mLength = in->ByteLength();
			}
		}
		else if (aValue->IsString())
		{
			mStringValue = new v8::String::Utf8Value(aValue);
			mBuffer = **mStringValue;
			mLength = mStringValue->length();
		}
	}

	//---------------------------------------------------------------------------------------
	virtual ~GetBuffer()
	{
		if (mStringValue)
		{
			delete mStringValue;
			mStringValue = nullptr;
		}
	}

	//---------------------------------------------------------------------------------------
	bool isValid() const
	{
		return mBuffer && mLength > 0;
	}

	//---------------------------------------------------------------------------------------
	char * getPtr() const
	{
		return mBuffer;
	}

	//---------------------------------------------------------------------------------------
	int getLength() const
	{
		return mLength;
	}
};

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

	int rc = Crypt_SignEx(in.getPtr(), in.getLength(), out.getPtr(), out.getLength(), &key->mKey, key->alg);

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
