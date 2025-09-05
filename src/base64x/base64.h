/*********************************************************************
* Filename:   base64.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding Base64 implementation.
*********************************************************************/

#ifndef BASE64_H
#define BASE64_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte

/*********************** FUNCTION DECLARATIONS **********************/
// Returns the size of the output. If called with out = NULL, will just return
// the size of what the output would have been (without a terminating NULL).
size_t base64_encode(const BYTE in[], BYTE out[], size_t len, int newline_flag);

// Returns the size of the output. If called with out = NULL, will just return
// the size of what the output would have been (without a terminating NULL).
size_t base64_decode(const BYTE in[], BYTE out[], size_t len);

/*********************** BASE64X FUNCTION DECLARATIONS **********************/
// BASE64X - Extended Base64 with selectable encoding modes
// Mode 0: Standard Base64, Mode 1: Base85, Mode 2: Randomized alphabet
void base64x_set_mode(int mode);
int base64x_get_mode(void);
size_t base64x_encode(const BYTE in[], BYTE out[], size_t len, int newline_flag);
size_t base64x_decode(const BYTE in[], BYTE out[], size_t len);

// Individual encoding functions
size_t base85_encode(const BYTE in[], BYTE out[], size_t len, int newline_flag);
size_t base85_decode(const BYTE in[], BYTE out[], size_t len);
size_t base64x_random_encode(const BYTE in[], BYTE out[], size_t len, int newline_flag);
size_t base64x_random_decode(const BYTE in[], BYTE out[], size_t len);

#endif   // BASE64_H
