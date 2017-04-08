#include <string>
#include <iostream>

#include "../src/libipriv.h"

class IprivKey
{
  IPRIV_KEY mKey;

public:
  IprivKey();
  virtual ~IprivKey();

  int loadSecretFromFile(std::string filePath, std::string password);

};


class Ipriv
{
public:
    static int initialize();
    static int done();
};

