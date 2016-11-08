/* R_RANDOM.H - header file for R_RANDOM.C
 */

/* Copyright (C) RSA Laboratories, a division of RSA Data Security,
     Inc., created 1991. All rights reserved.
 */

int R_GenerateBytes PROTO_LIST((unsigned char *, unsigned int, R_RANDOM_STRUCT *));
int R_RandomInit (R_RANDOM_STRUCT *randomStruct);
int R_RandomUpdate (R_RANDOM_STRUCT *randomStruct, unsigned char *block, unsigned int blockLen);
int R_GetRandomBytesNeeded (unsigned int *bytesNeeded, R_RANDOM_STRUCT *randomStruct);
void R_RandomFinal (R_RANDOM_STRUCT *randomStruct);

