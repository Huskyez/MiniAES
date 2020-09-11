#pragma once

#define MAKE_ERROR(severity, type) ((severity << 16) + type)

#define AES_OK MAKE_ERROR(0x00, 0x00)

#define AES_WRONG_CIPHERTEXT MAKE_ERROR(0x01, 0x01)
#define AES_WRONG_ARGS MAKE_ERROR(0x01, 0x02)
#define AES_NO_MEMORY MAKE_ERROR(0x02, 0x01)


#define AES_IS_ERROR(err) ((err) != AES_OK)
