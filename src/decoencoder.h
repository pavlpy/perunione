#ifndef DECOENCODER_H
#define DECOENCODER_H

#include <stdint.h>
#include "ellyptic.h"

/* Encryption rounds */
#define REP 7

/* Must be called once before enc/dec to build the inverse S-box */
void init_dectbl(void);

/* Encrypt/decrypt len bytes of string in-place using key */
void enc(const BigInt *key, char *string, int len);
void dec(const BigInt *key, char *string, int len);

#endif
