#ifndef IPRIVKEY_H
#define IPRIVKEY_H

#include <string>
#include <iostream>

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
    IPRIV_KEY mKey;

public:
    static void Init(v8::Local<v8::Object> exports);

private:
    IprivKey();
    virtual ~IprivKey();

    static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void OpenSecretKeyFromFile(const Nan::FunctionCallbackInfo<v8::Value> & info);
    static void Sign(const Nan::FunctionCallbackInfo<v8::Value> & info);
//    int Sign(nbind::Buffer message, nbind::Buffer result);
    static Nan::Persistent<v8::Function> constructor;
};

//---------------------------------------------------------------------------------------
#endif
