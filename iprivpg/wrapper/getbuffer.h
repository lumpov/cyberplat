#ifndef GETBUFFER_H
#define GETBUFFER_H

//---------------------------------------------------------------------------------------
class GetBuffer
{
	const v8::Local<v8::Value> & mValue;
	char * mBuffer;
	int mLength;

	v8::String::Utf8Value * mStringValue;

public:
	//---------------------------------------------------------------------------------------
	explicit GetBuffer(const v8::Local<v8::Value> & aValue) :
		mValue(aValue), mBuffer(0), mLength(0), mStringValue(0)
	{
//	    std::string inType = *v8::String::Utf8Value(aValue->ToObject()->ObjectProtoToString());
//	    printf("in object type: %s\n", inType.c_str());

#if V8_MAJOR_VERSION > 0 || V8_MINOR_VERSION > 10
		if (aValue->IsUint8Array())
		{
			v8::Uint8Array * in = v8::Uint8Array::Cast(*aValue);

		    if (in->HasBuffer())
			{
		    	mBuffer = (char *)in->Buffer()->GetContents().Data() + in->ByteOffset();
		    	mLength = in->ByteLength();
			}
		}
		else 
#endif            
            if (aValue->IsString())
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
			mStringValue = 0;
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


#endif
//---------------------------------------------------------------------------------------
