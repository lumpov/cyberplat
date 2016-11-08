/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/

#ifndef __ENG_RSAREF_H
#define __ENG_RSAREF_H

#include "ipriv.h"

int eng_rsaref_init(IPRIV_ENGINE* eng);
int eng_rsaref_done(IPRIV_ENGINE* eng);

int eng_rsaref_secret_key_new(IPRIV_KEY_BODY* src,IPRIV_KEY* k);
int eng_rsaref_secret_key_delete(IPRIV_KEY* k);

#endif
