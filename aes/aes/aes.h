#pragma once

#include <stdint.h>
#include <stdlib.h>

#define Nb 4

// values for AES 256 bit
#ifdef AES256
	#define Nk 8
	#define Nr 14

// values for AES 192 bit
#elif defined(AES192)
	#define Nk 6
	#define Nr 12

// values for AES 128 bit (default)
#else
	#define Nk 8
	#define Nr 10
#endif


// define a word as a 32 bit value
// (array of 4 bytes)
typedef struct _WORD {
	uint8_t val[Nb];
} WORD;



// void KeyExpansion(const uint8_t* key);

// void SubBytes();

// void ShiftRows();

// void MixColumns();
