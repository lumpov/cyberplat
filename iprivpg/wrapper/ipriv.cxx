
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


#include "nbind/nbind.h"

NBIND_GLOBAL()
{
	function(Crypt_Initialize);
	function(Crypt_Done);
}

NBIND_CLASS(IprivKey)
{
	construct<>();

	method(loadSecretFromFile);
}
