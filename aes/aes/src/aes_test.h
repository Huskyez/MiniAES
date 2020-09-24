#pragma once

#include "aes.h"

// This header file contains all function definitions
// in aes.c and type definitions from aes.h for the purpose of testing


uint8_t xtime(uint8_t val);

uint8_t multiply(uint8_t a, uint8_t b);

void KeyExpansion(const uint8_t *key, WORD **w);

void SubBytes();

void ShiftRows();

void MixColumns();

void AddRoundKey(const uint8_t round, const WORD *round_key);

void InvShiftRows();

void InvSubBytes();

void InvMixColumns();

void Cipher(const uint8_t *in, const WORD *round_key, uint8_t **out);

void InvCipher(const uint8_t *in, const WORD *round_key, uint8_t **out);


