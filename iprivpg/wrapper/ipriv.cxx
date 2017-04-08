
#include <string.h>

#include "ipriv.h"

IprivKey::IprivKey()
{
  memset(&mKey, 0, sizeof(mKey));
}

IprivKey::~IprivKey()
{
  Crypt_CloseKey(&mKey);
}

int IprivKey::loadSecretFromFile(std::string filePath, std::string password)
{
	std::cout << "load secret key\n";

	return -1;
}

int Ipriv::done()
{
	return Crypt_Done();
}

int Ipriv::initialize()
{
	return Crypt_Initialize();
}
