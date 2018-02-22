#ifndef IPRIVKEY_H
#define IPRIVKEY_H

#include <string>
#include <iostream>
#include <map>

#include <nan.h>

#include "../src/libipriv.h"

//---------------------------------------------------------------------------------------
void initialize(const Nan::FunctionCallbackInfo<v8::Value> & info);
void done(const Nan::FunctionCallbackInfo<v8::Value> & info);

//---------------------------------------------------------------------------------------
class IprivKey : public Nan::ObjectWrap
{
    int eng;
    int alg;
    IPRIV_KEY mSecretKey;

    std::string mPublicKeyPath;
    std::map<unsigned long, IPRIV_KEY> mPublicKeys;

public:
    static void Init(v8::Local<v8::Object> exports);

private:
    IprivKey();
    virtual ~IprivKey();

    // Construct new object
    static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static Nan::Persistent<v8::Function> constructor;

    // Open secret key
    static void OpenSecretKeyFromFile(const Nan::FunctionCallbackInfo<v8::Value> & info);

    // Sign message
    static void Sign(const Nan::FunctionCallbackInfo<v8::Value> & info);

    // Open public key
    int OpenPublicKeyFromFile(const std::string & aFileName, unsigned long aKeySerial);
    static void OpenPublicKeyFromFile(const Nan::FunctionCallbackInfo<v8::Value> & info);

    // Verify message
    static void Verify(const Nan::FunctionCallbackInfo<v8::Value> & info);
};

//---------------------------------------------------------------------------------------
#endif
