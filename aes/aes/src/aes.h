#pragma once

// This header file is to be included by the end user
// containing only the function definitions and macros
// the user needs to encrypt/decrypt

#include <stdint.h>
#include <stdlib.h>

#define Nb 4

// define a word as a 32 bit value
// (array of 4 bytes)
typedef struct _WORD {
	uint8_t val[Nb];
} WORD;

enum AESTYPE {
	AES128,
	AES192,
	AES256
};

// void KeyExpansion(const uint8_t* key, WORD** w);

// void SubBytes();

// void ShiftRows();

// void MixColumns();
