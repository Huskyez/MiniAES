#include "aes.h"
#include "aes_test.h"

#include <stdio.h>

//#define Nb 4

// // values for AES 256 bit
// #if defined(AES256)
// 	#define Nk 8
// 	#define Nr 14

// // values for AES 192 bit
// #elif defined(AES192)
// 	#define Nk 6
// 	#define Nr 12

// // values for AES 128 bit (default)
// #else
// 	#define Nk 4
// 	#define Nr 10
// #endif

static AESTYPE aestype = AES128;

static uint8_t Nk = 4;
static uint8_t Nr = 10;

static uint8_t state[4][4];
// static WORD* round_key;

static AES_ERR error;


const uint8_t Rcon[11] = {
	0xff, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};


const uint8_t s_box[256] = {
//	   0	 1     2 	 3	   4  	 5 	   6 	 7 	   8 	 9	   A 	 B 	   C 	 D 	   E     F
/*0*/ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
/*1*/ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
/*2*/ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
/*3*/ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
/*4*/ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
/*5*/ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
/*6*/ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
/*7*/ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
/*8*/ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
/*9*/ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
/*A*/ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
/*B*/ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
/*C*/ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
/*D*/ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
/*E*/ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
/*F*/ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t inv_s_box[256] = {
//	   0	 1     2 	 3	   4  	 5 	   6 	 7 	   8 	 9	   A 	 B 	   C 	 D 	   E     F	
/*0*/ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
/*1*/ 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
/*2*/ 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
/*3*/ 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
/*4*/ 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
/*5*/ 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
/*6*/ 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
/*7*/ 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
/*8*/ 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
/*9*/ 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
/*a*/ 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
/*b*/ 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
/*c*/ 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
/*d*/ 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
/*e*/ 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
/*f*/ 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};



// -----------------------------------------------------------------------------------------------------------------------------------------------------
// ----------------------------------------------------- PRIVATE FUNCTIONS -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------------------



inline uint8_t getSBoxValue(const uint8_t value)
{
	return s_box[value];
}

inline uint8_t getInvSBoxValue(const uint8_t value)
{
	return inv_s_box[value];
}

inline void SubWord(WORD* w)
{
	uint8_t j;
	for (j = 0; j < Nb; j++)
	{
		w->val[j] = getSBoxValue(w->val[j]);	
	} 
}


inline void RotWord(WORD* w)
{
	uint8_t j;
	uint8_t temp = w->val[0];
	for (j = 0; j < Nb - 1; j++)
	{
		w->val[j] = w->val[j + 1];
	}
	w->val[Nb - 1] = temp;
}

// multiply the polynomial val by x (i.e. 2 -> left shift)
// if the first bit is 1 the resulting polynomial will
// be of degree 8 and we reduce it by taking the multplication
// modulo m(x) = x^8 + x^4 + x^3 + x + 1
// which translates into XORing val by 0x1b
inline uint8_t xtime(uint8_t val)
{
	return (val << 1) ^ (((val >> 7) & 1) * 0x1b);
}

inline uint8_t multiply(uint8_t a, uint8_t b)
{
	uint8_t result = 0;

	// put the smaller value into b
	// (small optimization)
	if (b > a)
	{
		b ^= a;
		a ^= b;
		b ^= a;
	}

	uint8_t next = a;

	while (b > 0)
	{
		if (b & 1)
		{
			result ^= next;
		}
		b >>= 1;
		next = xtime(next);
	} 

	return result;
}


// key must have at least Nk * 4 bytes
void KeyExpansion(const uint8_t* key, WORD** w)
{
	if (w == NULL)
	{
		error = AES_WRONG_ARGS;
		return;
	}

	// this will be freed at the end of the encryption proess
	// TODO: add function name which frees this
	WORD* round_key = (WORD *)malloc(Nb * (Nr + 1) * sizeof(WORD));

	if (round_key == NULL)
	{
		error = AES_NO_MEMORY;
		return;
	}

	// tempory word
	WORD temp;

	uint8_t i;
	uint8_t j;
	for (i = 0; i < Nk; i++) 
	{

		for (j = 0; j < Nb; j++)
		{
			round_key[i].val[j] = key[4 * i + j];	
		}
	}

	for (i = Nk; i < Nb * (Nr + 1); i++)
	{
		temp = round_key[i - 1];
		
		if (i % Nk == 0)
		{
			RotWord(&temp);
			SubWord(&temp);
			temp.val[0] ^= Rcon[i / Nk];
		}
		else if (Nk > 6 && i % Nk == 4)
		{
			SubWord(&temp);
		}

		for (j = 0; j < Nb; j++)
		{
			round_key[i].val[j] = round_key[i - Nk].val[j] ^ temp.val[j];
		}
	}

	*w = round_key;

}


void AddRoundKey(const uint8_t round, const WORD* round_key)
{
	uint8_t i;
	uint8_t j;
	for (j = 0; j < Nb; j++)
	{
		for (i = 0; i < Nb; i++)
		{
			state[i][j] ^= round_key[Nb * round + j].val[i];
		}
	}
}


void SubBytes()
{
	uint8_t i;
	uint8_t j;
	for (i = 0; i < Nb; i++) 
	{
		for (j = 0; j < Nb; j++) 
		{
			state[i][j] = getSBoxValue(state[i][j]);
		}
	}
}

void InvSubBytes()
{
	uint8_t i;
	uint8_t j;
	for (i = 0; i < Nb; i++)
	{
		for (j = 0; j < Nb; j++)
		{
			state[i][j] = getInvSBoxValue(state[i][j]);
		}
	}
}


void ShiftRows() 
{
	uint8_t i;
	uint8_t j;
	for (i = 1; i < Nb; i++)
	{
		uint8_t temp[4];
		for (j = 0; j < Nb; j++) 
		{
			temp[j] = state[i][j];
		}
		for (j = 0; j < Nb; j++) 
		{
			state[i][j] = temp[(j + i) % Nb];
		}
	}
}

void InvShiftRows()
{
	uint8_t i;
	uint8_t j;
	for (i = 1; i < Nb; i++)
	{
		uint8_t temp[4];
		for (j = 0; j < Nb; j++)
		{
			temp[j] = state[i][j];
		}
		for (j = 0; j < Nb; j++)
		{
			state[i][j] = temp[(j - i + Nb) % Nb];
		}
	}
}


void MixColumns()
{
	uint8_t i;
	uint8_t j;
	uint8_t temp[Nb];
	for (j = 0; j < Nb; j++)
	{
		temp[0] = multiply(state[0][j], 0x02) ^ multiply(state[1][j], 0x03) ^ state[2][j] ^ state[3][j];
		temp[1] = state[0][j] ^ multiply(state[1][j], 0x02) ^ multiply(state[2][j], 0x03) ^ state[3][j];
		temp[2] = state[0][j] ^ state[1][j] ^ multiply(state[2][j], 0x02) ^ multiply(state[3][j], 0x03);
		temp[3] = multiply(state[0][j], 0x03) ^ state[1][j] ^ state[2][j] ^ multiply(state[3][j], 0x02);
	
		for (i = 0; i < Nb; i++)
		{
			state[i][j] = temp[i];
		}
	}
}

void InvMixColumns()
{
	uint8_t i;
	uint8_t j;
	uint8_t temp[Nb];
	for (j = 0; j < Nb; j++)
	{
		temp[0] = multiply(state[0][j], 0x0e) ^ multiply(state[1][j], 0x0b) ^ multiply(state[2][j], 0x0d) ^ multiply(state[3][j], 0x09);
		temp[1] = multiply(state[0][j], 0x09) ^ multiply(state[1][j], 0x0e) ^ multiply(state[2][j], 0x0b) ^ multiply(state[3][j], 0x0d);
		temp[2] = multiply(state[0][j], 0x0d) ^ multiply(state[1][j], 0x09) ^ multiply(state[2][j], 0x0e) ^ multiply(state[3][j], 0x0b);
		temp[3] = multiply(state[0][j], 0x0b) ^ multiply(state[1][j], 0x0d) ^ multiply(state[2][j], 0x09) ^ multiply(state[3][j], 0x0e);

		for (i = 0; i < Nb; i++)
		{
			state[i][j] = temp[i];
		}
	}
}


// sets the state to the given input
inline void setState(const uint8_t* in)
{
	uint8_t i;

	for (i = 0; i < 4 * Nb; i++)
	{
		state[i % Nb][i / Nb] = in[i];
	}
}

//sets the result from the end state
inline void getState(uint8_t* out)
{
	uint8_t i;
	uint8_t j;

	for (i = 0; i < Nb; i++)
	{
		for (j = 0; j < Nb; j++)
		{
			out[Nb * i + j] = state[j][i];
		}
	}
}


// assumes the input size is already 4 * Nb
void Cipher(const uint8_t* in, const WORD* round_key, uint8_t** out)
{
	uint8_t round;

	// will be freed after the whole string is encrypted
	// TODO: add function which frees this
	uint8_t* result = (uint8_t *)malloc(4 * Nb * sizeof(uint8_t));

	if (result == NULL)
	{
		//TODO: handle no memory
		return;
	}

	setState(in);
	
	//add the first round key
	AddRoundKey(0, round_key);

	// the fist Nr - 1 rounds
	for (round = 1; round < Nr; ++round)
	{
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(round, round_key);
	}
	
	//last round
	SubBytes();
	ShiftRows();
	AddRoundKey(Nr, round_key);

	getState(result);
	*out = result;
}


// reverses the Cipher method
// -> the procedure is done in reverse
// also assumes the input is of size 4 * Nb
void InvCipher(const uint8_t* in, const WORD* round_key, uint8_t** out)
{

	uint8_t round;
	// will be freed after the whole ciphertext is decrypted
	// TODO: add function which frees this
	uint8_t* result = (uint8_t *)malloc(4 * Nb * sizeof(uint8_t));

	if (result == NULL)
	{
		error = AES_NO_MEMORY;
		return;
	}

	setState(in);

	//add the last round key
	AddRoundKey(Nr, round_key);

	for (round = Nr - 1; round; round--)
	{
		InvShiftRows();
		InvSubBytes();
		AddRoundKey(round, round_key);
		InvMixColumns();
	}
	
	InvShiftRows();
	InvSubBytes();
	AddRoundKey(0, round_key);

	getState(result);
	*out = result;
}


// -----------------------------------------------------------------------------------------------------------------------------------------------------
// ----------------------------------------------------- PUBLIC API FUNCTIONS --------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------------------


void setAESType(AESTYPE type)
{
	aestype = type;
	switch (aestype)
	{
		case AES192:
			Nk = 6;
			Nr = 12;
			break;
		case AES256:
			Nk = 8;
			Nr = 14;
			break;
		default:
			Nk = 4;
			Nr = 10;
			break;
	}
}

AESTYPE getAESType()
{
	return aestype;
}


// ---------------------------------------------- ECB -------------------------------------------------------------------------------------------------

AES_ERR ecb_aes_encrypt(const uint8_t* plaintext, const size_t plaintext_size, const uint8_t* key, uint8_t** ciphertext, size_t* ciphertext_size)
{

	if (ciphertext_size == NULL || ciphertext == NULL)
	{
		error = AES_WRONG_ARGS;
		return AES_WRONG_ARGS;
	}

	uint8_t i;
	// number of blocks in the plaintext
	size_t blocks = plaintext_size / (Nb * 4);

	//remaining number of bytes in the last block
	size_t rest = plaintext_size % (Nb * 4);


	// if rest is 0, i.e. length of plaintext is a multiple of Nb * 4
	// we still add padding so we don't have to verify later if padding was
	// added or not
	size_t padding_size = Nb * 4 - rest;

	//add padding
	uint8_t* padded_plaintext = (uint8_t *) malloc((padding_size + plaintext_size) * sizeof(uint8_t));
	if (padded_plaintext == NULL)
	{
		error = AES_NO_MEMORY;
		return AES_NO_MEMORY;
	}

	memcpy(padded_plaintext, plaintext, plaintext_size);

	padded_plaintext[plaintext_size] = 0x80;
	for (i = plaintext_size + 1; i < plaintext_size + padding_size; i++)
	{
		padded_plaintext[i] = 0x00;		
	}

	*ciphertext_size = plaintext_size + padding_size;

	uint8_t* cipher = (uint8_t *)malloc(*ciphertext_size * sizeof(uint8_t));
	if (cipher == NULL) 
	{
		free(padded_plaintext);
		error = AES_NO_MEMORY;
		return AES_NO_MEMORY;
	}

	WORD *round_key;
	KeyExpansion(key, &round_key);

	uint8_t* current_cipher_block;

	for (i = 0; i < blocks + 1; i++)
	{
		Cipher(padded_plaintext + (i * Nb * 4), round_key, &current_cipher_block);
		memcpy(cipher + (i * Nb * 4), current_cipher_block, Nb * 4);
		free(current_cipher_block);
	}

	*ciphertext = cipher;
	
	free(round_key);
	free(padded_plaintext);

	return AES_OK;
}


AES_ERR ecb_aes_decrypt(const uint8_t* ciphertext, const size_t ciphertext_size, const uint8_t* key, uint8_t** plaintext, size_t* plaintext_size)
{

	if (plaintext == NULL || plaintext_size == NULL)
	{
		error = AES_WRONG_ARGS;
		return AES_WRONG_ARGS;
	}

	uint8_t i;

	size_t blocks = ciphertext_size / (Nb * 4);

	if (ciphertext_size % (Nb * 4) != 0)
	{
		error = AES_WRONG_CIPHERTEXT;
		return AES_WRONG_CIPHERTEXT;
	}

	uint8_t *result = (uint8_t *)malloc(ciphertext_size * sizeof(uint8_t));
	if (result == NULL)
	{
		error = AES_NO_MEMORY;
		return AES_NO_MEMORY;
	}	


	WORD *round_key;
	KeyExpansion(key, &round_key);

	// decipher ciphertext block by block
	uint8_t* plaintext_block;

	for (i = 0; i < blocks; i++)
	{
		InvCipher(ciphertext + (i * Nb * 4), round_key, &plaintext_block);
		memcpy(result + (i * Nb * 4), plaintext_block, Nb * 4);
		free(plaintext_block);
	}

	size_t size = ciphertext_size;

	// remove pading
	for (i = ciphertext_size - 1; i; i--)
	{
		if (result[i] == 0x00)
		{
			size--;
		}
		if (result[i] == 0x80)
		{
			size--;
			break;
		}
	}
	
	uint8_t *unpadded_result = (uint8_t *)malloc(size * sizeof(uint8_t));
	if (unpadded_result == NULL)
	{
		free(result);
		free(round_key);
		error = AES_NO_MEMORY;
		return AES_NO_MEMORY;
	}
	memcpy(unpadded_result, result, size);


	*plaintext_size = size;
	*plaintext = unpadded_result;

	free(result);
	free(round_key);

	return AES_OK;
}


// ---------------------------------------------- CBC -------------------------------------------------------------------------------------------------

AES_ERR cbc_aes_encrypt(const uint8_t* plaintext, const size_t plaintext_size, const uint8_t* key, uint8_t** ciphertext, size_t* ciphertext_size, const uint8_t* iv)
{
	if (ciphertext_size == NULL || ciphertext == NULL)
	{
		error = AES_WRONG_ARGS;
		return AES_WRONG_ARGS;
	}

	uint8_t i;
	uint8_t j;

	// number of blocks in the plaintext
	size_t blocks = plaintext_size / (Nb * 4);

	//remaining number of bytes in the last block
	size_t rest = plaintext_size % (Nb * 4);


	// if rest is 0, i.e. length of plaintext is a multiple of Nb * 4
	// we still add padding so we don't have to verify later if padding was
	// added or not
	size_t padding_size = Nb * 4 - rest;

	//add padding
	uint8_t* padded_plaintext = (uint8_t *) malloc((padding_size + plaintext_size) * sizeof(uint8_t));
	if (padded_plaintext == NULL)
	{
		error = AES_NO_MEMORY;
		return AES_NO_MEMORY;
	}

	memcpy(padded_plaintext, plaintext, plaintext_size);

	padded_plaintext[plaintext_size] = 0x80;
	for (i = plaintext_size + 1; i < plaintext_size + padding_size; i++)
	{
		padded_plaintext[i] = 0x00;		
	}

	*ciphertext_size = plaintext_size + padding_size;

	uint8_t* cipher = (uint8_t *)malloc(*ciphertext_size * sizeof(uint8_t));
	if (cipher == NULL) 
	{
		free(padded_plaintext);
		error = AES_NO_MEMORY;
		return AES_NO_MEMORY;
	}


	// current_block is the block to be encrypted that was already xored
	uint8_t* current_block = (uint8_t*)malloc(Nb * 4 * sizeof(uint8_t));
	if (current_block == NULL)
	{
		free(padded_plaintext);
		free(cipher);
		error = AES_NO_MEMORY;
		return AES_NO_MEMORY;	
	}
	for (j = 0; j < Nb * 4; j++) 
	{
		current_block = padded_plaintext[j] ^ iv[j];
	}

	uint8_t *current_cipher_block;

	WORD *round_key;
	KeyExpansion(key, &round_key);

	// cipher for the first block
	Cipher(current_block, round_key, &current_cipher_block);
	memcpy(cipher + (i * Nb * 4), current_cipher_block, Nb * 4);

	for (i = 1; i < blocks + 1; i++)
	{
		// change the block to be encrypted
		for (j = 0; j < Nb * 4; j++)
		{
			current_block[j] = current_cipher_block[j] ^ padded_plaintext[i * Nb * 4 + j];		
		}
		free(current_cipher_block);
		Cipher(current_block, round_key, &current_cipher_block);
		memcpy(cipher + (i * Nb * 4), current_cipher_block, Nb * 4);
	}

	
	free(current_block);
	free(current_cipher_block);
	free(round_key);
}


