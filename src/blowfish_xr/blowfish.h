/*********************************************************************
* Filename:   blowfish.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding Blowfish implementation.
*********************************************************************/

#ifndef BLOWFISH_H
#define BLOWFISH_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int WORD;              // 32-bit word, change to "long" for 16-bit machines

/****************************** MACROS ******************************/
#define BLOWFISH_BLOCK_SIZE 8           // Blowfish operates on 8 bytes at a time

/**************************** DATA STRUCTURES **********************/
typedef struct {
	WORD p[18];                         // P-array
	WORD s[4][256];                     // S-boxes
} BLOWFISH_KEY;

typedef struct {
	WORD p[34];                         // Extended P-array for Blowfish-XR
	WORD s[4][256];                     // Extended S-boxes for Blowfish-XR
} BLOWFISH_XR_KEY;

/*********************** FUNCTION DECLARATIONS **********************/
///////////////////
// Blowfish
///////////////////
void blowfish_key_setup(const BYTE user_key[], BLOWFISH_KEY *keystruct, size_t len);
void blowfish_encrypt(const BYTE in[], BYTE out[], const BLOWFISH_KEY *keystruct);
void blowfish_decrypt(const BYTE in[], BYTE out[], const BLOWFISH_KEY *keystruct);

///////////////////
// Blowfish-XR (Extended Rounds)
///////////////////
// Blowfish-XR uses 32 rounds and regenerated S-boxes/P-boxes for enhanced security
void blowfish_xr_key_setup(const BYTE user_key[], BLOWFISH_XR_KEY *keystruct, size_t len);
void blowfish_xr_encrypt(const BYTE in[], BYTE out[], const BLOWFISH_XR_KEY *keystruct);
void blowfish_xr_decrypt(const BYTE in[], BYTE out[], const BLOWFISH_XR_KEY *keystruct);

///////////////////
// Test functions
///////////////////
int blowfish_test();
int blowfish_xr_test();

#endif   // BLOWFISH_H
