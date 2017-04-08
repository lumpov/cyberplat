
#include <string.h>

#include "ipriv.h"

//---------------------------------------------------------------------------------------
IprivKey::IprivKey() :
  eng(IPRIV_ENGINE_RSAREF),  // Select crypto engine
  alg(IPRIV_ALG_MD5)         // Select crypto hash algorithm
{
  memset(&mKey, 0, sizeof(mKey));
}

//---------------------------------------------------------------------------------------
IprivKey::~IprivKey()
{
  Crypt_CloseKey(&mKey);
}

//---------------------------------------------------------------------------------------
int IprivKey::initialize()
{
	return Crypt_Initialize();
}

//---------------------------------------------------------------------------------------
int IprivKey::done()
{
	return Crypt_Done();
}

//---------------------------------------------------------------------------------------
int IprivKey::OpenSecretKeyFromFile(std::string filePath, std::string password)
{
	int rc = Crypt_OpenSecretKeyFromFile(eng, filePath.c_str(), password.c_str(), &mKey);

//	std::cerr << "open = " << rc << std::endl;

	return rc;
}

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

//---------------------------------------------------------------------------------------
#include "nbind/nbind.h"

//---------------------------------------------------------------------------------------
NBIND_CLASS(IprivKey)
{
	construct<>();

	method(initialize);
	method(done);

	method(OpenSecretKeyFromFile);
	method(Sign);
}

//---------------------------------------------------------------------------------------
