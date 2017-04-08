#include <string>
#include <iostream>

#include "../src/libipriv.h"
#include "nbind/api.h"

//---------------------------------------------------------------------------------------
class IprivKey
{
  int eng;
  int alg;
  IPRIV_KEY mKey;

public:
  IprivKey();
  virtual ~IprivKey();

  static int initialize();
  static int done();

  int OpenSecretKeyFromFile(std::string filePath, std::string password);
  int Sign(nbind::Buffer message, nbind::Buffer result);

};

//---------------------------------------------------------------------------------------
