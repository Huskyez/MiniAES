#include <assert.h> 
#include "aes_test.h"

#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

void CipherTest128bitApendixB()
{

	uint8_t input[16] = {
		0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
	};

	uint8_t cipher_key_128[16] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};

	uint8_t* result;
	WORD* round_key;
	KeyExpansion(cipher_key_128, &round_key);
	Cipher(input, round_key, &result);

	uint8_t output[16] = {
		0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
	};
	
	uint8_t i;
	for (i = 0; i < 16; i++)
	{
		assert(output[i] == result[i]);
	}
	free(round_key);
	free(result);
}

void DecipherTest128bit()
{

	uint8_t output[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};

	uint8_t cipher_key_128[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};

	uint8_t input[16] = {
		0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
	};

	uint8_t* result;
	WORD* round_key;
	KeyExpansion(cipher_key_128, &round_key);
	InvCipher(input, round_key, &result);

	uint8_t i;
	for (i = 0; i < 16; i++)
	{
		assert(output[i] == result[i]);
	}
	free(round_key);
	free(result);
}

void CipherTest128bit()
{

	uint8_t input[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};

	uint8_t cipher_key_128[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};

	uint8_t output[16] = {
		0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
	};

	uint8_t* result;
	WORD* round_key;
	KeyExpansion(cipher_key_128, &round_key);
	Cipher(input, round_key, &result);

	uint8_t i;
	for (i = 0; i < 16; i++)
	{
		assert(output[i] == result[i]);
	}
	free(round_key);
	free(result);
}

void MultiplyTest()
{
	assert(xtime(0x57) == 0xae);
	assert(xtime(0xae) == 0x47);
	assert(xtime(0x47) == 0x8e);
	assert(xtime(0x8e) == 0x07);


	assert(multiply(0x13, 0x57) == 0xfe);
	assert(multiply(0x13, 0x57) == multiply(0x57, 0x13));
	assert(multiply(0x08, 0x57) == 0x8e);
	assert(multiply(0x4f, 0x02) == xtime(0x4f));
}


void ECB_AES128_Test()
{
	uint8_t key[Nb * 4] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};

	uint8_t plaintext[64] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
	};

	uint8_t ciphertext[64] = {
		0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
		0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
		0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
		0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4
	};

	uint8_t i;

	// test encryption
	size_t encryption_size;
	uint8_t *encryption;
	
	ecb_aes_encrypt(plaintext, 4 * 4 * Nb, key, &encryption, &encryption_size);

	// encryption_size has padding as well
	assert(encryption_size == 4 * 4 * (Nb + 1));

	for (i = 0; i < 64; i++)
	{
		assert(ciphertext[i] == encryption[i]);
	}

	

	// test decryption
	size_t decryption_size;
	uint8_t *decryption;

	ecb_aes_decrypt(encryption, encryption_size, key, &decryption, &decryption_size);

	// decryption_size has to be 64 i.e. the size of the plaintext
	assert(decryption_size == 64);

	for (i = 0; i < 64; i++)
	{
		assert(plaintext[i] == decryption[i]);
	}
	free(encryption);
	free(decryption);
}

void ECB_AES192_Test()
{
	uint8_t key[Nb * 6] = {
		0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
	};

	uint8_t plaintext[64] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
	};

	uint8_t ciphertext[64] = {
		0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc,
		0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a, 0xd3, 0xad, 0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef,
		0xef, 0x7a, 0xfd, 0x22, 0x70, 0xe2, 0xe6, 0x0a, 0xdc, 0xe0, 0xba, 0x2f, 0xac, 0xe6, 0x44, 0x4e,
		0x9a, 0x4b, 0x41, 0xba, 0x73, 0x8d, 0x6c, 0x72, 0xfb, 0x16, 0x69, 0x16, 0x03, 0xc1, 0x8e, 0x0e
	};

	uint8_t i;

	// test encryption
	size_t encryption_size;
	uint8_t *encryption;
	
	ecb_aes_encrypt(plaintext, 4 * 4 * Nb, key, &encryption, &encryption_size);

	// encryption_size has padding as well
	assert(encryption_size == 4 * 4 * (Nb + 1));

	for (i = 0; i < 64; i++)
	{
		assert(ciphertext[i] == encryption[i]);
	}

	// test decryption
	size_t decryption_size;
	uint8_t *decryption;

	ecb_aes_decrypt(encryption, encryption_size, key, &decryption, &decryption_size);

	// decryption_size has to be 64 i.e. the size of the plaintext
	assert(decryption_size == 64);

	for (i = 0; i < 64; i++)
	{
		assert(plaintext[i] == decryption[i]);
	}
	free(encryption);
	free(decryption);
}

void ECB_AES256_Test()
{
	uint8_t key[8 * Nb] = {
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
	};

	uint8_t plaintext[64] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
	};

	uint8_t ciphertext[64] = {
		0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
		0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26, 0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70,
		0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9, 0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d,
		0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff, 0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7
	};

	uint8_t i;

	// test encryption
	size_t encryption_size;
	uint8_t *encryption;
	
	ecb_aes_encrypt(plaintext, 4 * 4 * Nb, key, &encryption, &encryption_size);

	// encryption_size has padding as well
	assert(encryption_size == 4 * 4 * (Nb + 1));

	for (i = 0; i < 64; i++)
	{
		assert(ciphertext[i] == encryption[i]);
	}

	// test decryption
	size_t decryption_size;
	uint8_t *decryption;

	ecb_aes_decrypt(encryption, encryption_size, key, &decryption, &decryption_size);

	// decryption_size has to be 64 i.e. the size of the plaintext
	assert(decryption_size == 64);

	for (i = 0; i < 64; i++)
	{
		assert(plaintext[i] == decryption[i]);
	}
	free(encryption);
	free(decryption);
}

void KeyExpansionTest128bit()
{
	uint8_t i;

	uint8_t cipher_key_128[16] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
	WORD key_expansion_128[4];

	WORD* result;

	key_expansion_128[0].val[0] = 0x2b;
	key_expansion_128[0].val[1] = 0x7e;
	key_expansion_128[0].val[2] = 0x15;
	key_expansion_128[0].val[3] = 0x16;

	key_expansion_128[1].val[0] = 0x28;
	key_expansion_128[1].val[1] = 0xae;
	key_expansion_128[1].val[2] = 0xd2;
	key_expansion_128[1].val[3] = 0xa6;

	key_expansion_128[2].val[0] = 0xab;
	key_expansion_128[2].val[1] = 0xf7;
	key_expansion_128[2].val[2] = 0x15;
	key_expansion_128[2].val[3] = 0x88;

	key_expansion_128[3].val[0] = 0x09;
	key_expansion_128[3].val[1] = 0xcf;
	key_expansion_128[3].val[2] = 0x4f;
	key_expansion_128[3].val[3] = 0x3c;


	KeyExpansion(cipher_key_128, &result);

	for (i = 0; i < 4; i++)
	{
		assert(key_expansion_128[i].val[0] == result[i].val[0]);
		assert(key_expansion_128[i].val[1] == result[i].val[1]);
		assert(key_expansion_128[i].val[2] == result[i].val[2]);
		assert(key_expansion_128[i].val[3] == result[i].val[3]);
	}

	free(result);
}


void KeyExpansionTest192bit()
{
	uint8_t i;
	uint8_t j;

	uint8_t key[24] = {
		0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
		0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
	};
	
	WORD key_expansion_192[6];

	key_expansion_192[0].val[0] = 0x8e;
	key_expansion_192[0].val[1] = 0x73;
	key_expansion_192[0].val[2] = 0xb0;
	key_expansion_192[0].val[3] = 0xf7;

	key_expansion_192[1].val[0] = 0xda;
	key_expansion_192[1].val[1] = 0x0e;
	key_expansion_192[1].val[2] = 0x64;
	key_expansion_192[1].val[3] = 0x52;

	key_expansion_192[2].val[0] = 0xc8;
	key_expansion_192[2].val[1] = 0x10;
	key_expansion_192[2].val[2] = 0xf3;
	key_expansion_192[2].val[3] = 0x2b;

	key_expansion_192[3].val[0] = 0x80;
	key_expansion_192[3].val[1] = 0x90;
	key_expansion_192[3].val[2] = 0x79;
	key_expansion_192[3].val[3] = 0xe5;

	key_expansion_192[4].val[0] = 0x62;
	key_expansion_192[4].val[1] = 0xf8;
	key_expansion_192[4].val[2] = 0xea;
	key_expansion_192[4].val[3] = 0xd2;

	key_expansion_192[5].val[0] = 0x52;
	key_expansion_192[5].val[1] = 0x2c;
	key_expansion_192[5].val[2] = 0x6b;
	key_expansion_192[5].val[3] = 0x7b;

	WORD* result;

	KeyExpansion(key, &result);

	for (i = 0; i < 6; i++)
	{
		for (j = 0; j < Nb; j++)
		{
			assert(result[i].val[j] == key_expansion_192[i].val[j]);
		}
	}

	free(result);

}

void KeyExpansionTest256bit()
{
	uint8_t i;
	uint8_t j;
	
	uint8_t key[32] = {
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
	};

	WORD key_expansion_256[8];

	key_expansion_256[0].val[0] = 0x60;
	key_expansion_256[0].val[1] = 0x3d;
	key_expansion_256[0].val[2] = 0xeb;
	key_expansion_256[0].val[3] = 0x10;

	key_expansion_256[1].val[0] = 0x15;
	key_expansion_256[1].val[1] = 0xca;
	key_expansion_256[1].val[2] = 0x71;
	key_expansion_256[1].val[3] = 0xbe;

	key_expansion_256[2].val[0] = 0x2b;
	key_expansion_256[2].val[1] = 0x73;
	key_expansion_256[2].val[2] = 0xae;
	key_expansion_256[2].val[3] = 0xf0;

	key_expansion_256[3].val[0] = 0x85;
	key_expansion_256[3].val[1] = 0x7d;
	key_expansion_256[3].val[2] = 0x77;
	key_expansion_256[3].val[3] = 0x81;

	key_expansion_256[4].val[0] = 0x1f;
	key_expansion_256[4].val[1] = 0x35;
	key_expansion_256[4].val[2] = 0x2c;
	key_expansion_256[4].val[3] = 0x07;

	key_expansion_256[5].val[0] = 0x3b;
	key_expansion_256[5].val[1] = 0x61;
	key_expansion_256[5].val[2] = 0x08;
	key_expansion_256[5].val[3] = 0xd7;

	key_expansion_256[6].val[0] = 0x2d;
	key_expansion_256[6].val[1] = 0x98;
	key_expansion_256[6].val[2] = 0x10;
	key_expansion_256[6].val[3] = 0xa3;

	key_expansion_256[7].val[0] = 0x09;
	key_expansion_256[7].val[1] = 0x14;
	key_expansion_256[7].val[2] = 0xdf;
	key_expansion_256[7].val[3] = 0xf4;


	WORD* result;

	KeyExpansion(key, &result);

	for (i = 0; i < 8; i++)
	{
		for (j = 0; j < Nb; j++)
		{
			assert(result[i].val[j] == key_expansion_256[i].val[j]);
		}
	}

	free(result);
}	

int main(int argc, char** argv)
{
	MultiplyTest();
	
	// --------------- 128 bit tests -----------------------------------------------

	setAESType(AES128);

	KeyExpansionTest128bit();
	
	CipherTest128bitApendixB();

	CipherTest128bit();

	DecipherTest128bit();

	ECB_AES128_Test();
	
	_CrtDumpMemoryLeaks();


	// --------------- 192 bit tests -----------------------------------------------

	setAESType(AES192);
	
	KeyExpansionTest192bit();

	ECB_AES192_Test();

	// --------------- 256 bit tests -----------------------------------------------

	setAESType(AES256);
	
	KeyExpansionTest256bit();

	ECB_AES256_Test();

	_CrtDumpMemoryLeaks();


}