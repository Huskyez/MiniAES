#pragma once

// This header file is to be included by the end user
// containing only the function definitions and macros
// the user needs to encrypt/decrypt

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aes_error.h"

#define Nb 4

#define BLOCK_SIZE (Nb * 4)

// Note: AES_ERR is a redefinition of an unsigned 32 bit integer
// almost all functions return this
#define AES_ERR uint32_t

// define a word as a 32 bit value
// (array of 4 bytes)
typedef struct _WORD {
	uint8_t val[Nb];
} WORD;

typedef enum _AESTYPE {
	AES128 = 0x1337,
	AES192,
	AES256
} AESTYPE;

// if you want to change the key length to be 192 or 256 bits
// call this function with AES192 / AES256 respectevely
// before calling anything else from this lib
// all possible values for AESTYPE = {AES128, AES192, AES256}
void setAESType(AESTYPE type);

// get the current AES type 
AESTYPE getAESType();

// encrypt the given plaintext using the Electronic Codebook method
// this function padds the plaintext, so that the length is a multiple of 32 (default block size for AES standard)
// result is returned in ciphertext (which will be longer than the plaintext because of padding)
// length of the resulting ciphertext is returned in ciphertext_size (number of bytes)
// Note: setAESType function must be called before calling this one in order to set the key length - 128 bits by default
AES_ERR ecb_aes_encrypt(const uint8_t *plaintext, const size_t plaintext_size, const uint8_t *key, uint8_t **ciphertext, size_t *ciphertext_size);

// decrypt the given ciphertext using the Electronic Codebook method
// the length of the ciphertext must be a multiple of 32
// length of key must be of the specified length (128 / 192 / 256 bits specified with the setAESType function)
// result is returned in plaintext (without the padding)
// length of the plaintext is returned in plaintext_size (number of bytes)
AES_ERR ecb_aes_decrypt(const uint8_t *ciphertext, const size_t ciphertext_size, const uint8_t *key, uint8_t **plaintext, size_t *plaintext_size);


AES_ERR cbc_aes_encrypt(const uint8_t *plaintext, const size_t plaintext_size, const uint8_t *key, uint8_t **ciphertext, size_t *ciphertext_size, const uint8_t *iv);

AES_ERR cbc_aes_decrypt(const uint8_t* ciphertext, const size_t ciphertext_size, const uint8_t* key, uint8_t** plaintext, size_t* plaintext_size, const uint8_t* iv);

