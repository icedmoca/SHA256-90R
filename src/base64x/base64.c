/*********************************************************************
* Filename:   base64.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Implementation of the Base64 encoding algorithm.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdlib.h>
#include "base64.h"

/****************************** MACROS ******************************/
#define NEWLINE_INVL 76

/**************************** VARIABLES *****************************/
// Note: To change the charset to a URL encoding, replace the '+' and '/' with '*' and '-'
static const BYTE charset[]={"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};

// BASE64X - Extended Base64 with selectable encoding modes
// Mode 0: Standard Base64
// Mode 1: Base85 (ASCII85) encoding
// Mode 2: Randomized alphabet for obfuscation
static const BYTE base85_charset[] = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
static const BYTE base64x_random_charset[] = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/";

// Global encoding mode (0=Base64, 1=Base85, 2=Randomized)
static int base64x_mode = 0;

/*********************** FUNCTION DEFINITIONS ***********************/
BYTE revchar(char ch)
{
	if (ch >= 'A' && ch <= 'Z')
		ch -= 'A';
	else if (ch >= 'a' && ch <='z')
		ch = ch - 'a' + 26;
	else if (ch >= '0' && ch <='9')
		ch = ch - '0' + 52;
	else if (ch == '+')
		ch = 62;
	else if (ch == '/')
		ch = 63;

	return(ch);
}

size_t base64_encode(const BYTE in[], BYTE out[], size_t len, int newline_flag)
{
	size_t idx, idx2, blks, blk_ceiling, left_over, newline_count = 0;

	blks = (len / 3);
	left_over = len % 3;

	if (out == NULL) {
		idx2 = blks * 4 ;
		if (left_over)
			idx2 += 4;
		if (newline_flag)
			idx2 += len / 57;   // (NEWLINE_INVL / 4) * 3 = 57. One newline per 57 input bytes.
	}
	else {
		// Since 3 input bytes = 4 output bytes, determine out how many even sets of
		// 3 bytes the input has.
		blk_ceiling = blks * 3;
		for (idx = 0, idx2 = 0; idx < blk_ceiling; idx += 3, idx2 += 4) {
			out[idx2]     = charset[in[idx] >> 2];
			out[idx2 + 1] = charset[((in[idx] & 0x03) << 4) | (in[idx + 1] >> 4)];
			out[idx2 + 2] = charset[((in[idx + 1] & 0x0f) << 2) | (in[idx + 2] >> 6)];
			out[idx2 + 3] = charset[in[idx + 2] & 0x3F];
			// The offical standard requires a newline every 76 characters.
			// (Eg, first newline is character 77 of the output.)
			if (((idx2 - newline_count + 4) % NEWLINE_INVL == 0) && newline_flag) {
				out[idx2 + 4] = '\n';
				idx2++;
				newline_count++;
			}
		}

		if (left_over == 1) {
			out[idx2]     = charset[in[idx] >> 2];
			out[idx2 + 1] = charset[(in[idx] & 0x03) << 4];
			out[idx2 + 2] = '=';
			out[idx2 + 3] = '=';
			idx2 += 4;
		}
		else if (left_over == 2) {
			out[idx2]     = charset[in[idx] >> 2];
			out[idx2 + 1] = charset[((in[idx] & 0x03) << 4) | (in[idx + 1] >> 4)];
			out[idx2 + 2] = charset[(in[idx + 1] & 0x0F) << 2];
			out[idx2 + 3] = '=';
			idx2 += 4;
		}
	}

	return(idx2);
}

size_t base64_decode(const BYTE in[], BYTE out[], size_t len)
{
	BYTE ch;
	size_t idx, idx2, blks, blk_ceiling, left_over;

	if (in[len - 1] == '=')
		len--;
	if (in[len - 1] == '=')
		len--;

	blks = len / 4;
	left_over = len % 4;

	if (out == NULL) {
		if (len >= 77 && in[NEWLINE_INVL] == '\n')   // Verify that newlines where used.
			len -= len / (NEWLINE_INVL + 1);
		blks = len / 4;
		left_over = len % 4;

		idx = blks * 3;
		if (left_over == 2)
			idx ++;
		else if (left_over == 3)
			idx += 2;
	}
	else {
		blk_ceiling = blks * 4;
		for (idx = 0, idx2 = 0; idx2 < blk_ceiling; idx += 3, idx2 += 4) {
			if (in[idx2] == '\n')
				idx2++;
			out[idx]     = (revchar(in[idx2]) << 2) | ((revchar(in[idx2 + 1]) & 0x30) >> 4);
			out[idx + 1] = (revchar(in[idx2 + 1]) << 4) | (revchar(in[idx2 + 2]) >> 2);
			out[idx + 2] = (revchar(in[idx2 + 2]) << 6) | revchar(in[idx2 + 3]);
		}

		if (left_over == 2) {
			out[idx]     = (revchar(in[idx2]) << 2) | ((revchar(in[idx2 + 1]) & 0x30) >> 4);
			idx++;
		}
		else if (left_over == 3) {
			out[idx]     = (revchar(in[idx2]) << 2) | ((revchar(in[idx2 + 1]) & 0x30) >> 4);
			out[idx + 1] = (revchar(in[idx2 + 1]) << 4) | (revchar(in[idx2 + 2]) >> 2);
			idx += 2;
		}
	}

	return(idx);
}

/*********************** BASE64X FUNCTION DEFINITIONS ***********************/
// Set the encoding mode for BASE64X
void base64x_set_mode(int mode)
{
	if (mode >= 0 && mode <= 2)
		base64x_mode = mode;
}

// Get current encoding mode
int base64x_get_mode(void)
{
	return base64x_mode;
}

// Base85 character lookup
BYTE revchar_base85(char ch)
{
	int i;
	for (i = 0; i < 85; i++) {
		if (base85_charset[i] == ch)
			return i;
	}
	return 0; // Default to 0 if not found
}

// Randomized Base64 character lookup
BYTE revchar_random(char ch)
{
	int i;
	for (i = 0; i < 64; i++) {
		if (base64x_random_charset[i] == ch)
			return i;
	}
	return 0; // Default to 0 if not found
}

// BASE64X encoding with selectable mode
size_t base64x_encode(const BYTE in[], BYTE out[], size_t len, int newline_flag)
{
	if (base64x_mode == 1) {
		// Base85 encoding
		return base85_encode(in, out, len, newline_flag);
	} else if (base64x_mode == 2) {
		// Randomized Base64 encoding
		return base64x_random_encode(in, out, len, newline_flag);
	} else {
		// Standard Base64 encoding
		return base64_encode(in, out, len, newline_flag);
	}
}

// BASE64X decoding with selectable mode
size_t base64x_decode(const BYTE in[], BYTE out[], size_t len)
{
	if (base64x_mode == 1) {
		// Base85 decoding
		return base85_decode(in, out, len);
	} else if (base64x_mode == 2) {
		// Randomized Base64 decoding
		return base64x_random_decode(in, out, len);
	} else {
		// Standard Base64 decoding
		return base64_decode(in, out, len);
	}
}

// Base85 encoding implementation
size_t base85_encode(const BYTE in[], BYTE out[], size_t len, int newline_flag)
{
	size_t idx, idx2, blks, blk_ceiling, left_over, newline_count = 0;

	blks = (len / 4);
	left_over = len % 4;

	if (out == NULL) {
		idx2 = blks * 5;
		if (left_over)
			idx2 += 5;
		if (newline_flag)
			idx2 += len / 60; // One newline per 60 input bytes
	}
	else {
		blk_ceiling = blks * 4;
		for (idx = 0, idx2 = 0; idx < blk_ceiling; idx += 4, idx2 += 5) {
			// Convert 4 bytes to 32-bit value
			unsigned long value = ((unsigned long)in[idx] << 24) |
								 ((unsigned long)in[idx + 1] << 16) |
								 ((unsigned long)in[idx + 2] << 8) |
								 (unsigned long)in[idx + 3];
			
			// Convert to Base85
			out[idx2 + 4] = base85_charset[value % 85];
			value /= 85;
			out[idx2 + 3] = base85_charset[value % 85];
			value /= 85;
			out[idx2 + 2] = base85_charset[value % 85];
			value /= 85;
			out[idx2 + 1] = base85_charset[value % 85];
			value /= 85;
			out[idx2] = base85_charset[value % 85];
			
			// Add newlines
			if (((idx2 - newline_count + 5) % 60 == 0) && newline_flag) {
				out[idx2 + 5] = '\n';
				idx2++;
				newline_count++;
			}
		}

		// Handle remaining bytes
		if (left_over > 0) {
			unsigned long value = 0;
			for (int i = 0; i < left_over; i++) {
				value |= ((unsigned long)in[idx + i]) << (24 - i * 8);
			}
			
			for (int i = 4; i >= 0; i--) {
				out[idx2 + i] = base85_charset[value % 85];
				value /= 85;
			}
			idx2 += 5;
		}
	}

	return(idx2);
}

// Base85 decoding implementation
size_t base85_decode(const BYTE in[], BYTE out[], size_t len)
{
	size_t idx, idx2, blks, blk_ceiling, left_over;

	blks = len / 5;
	left_over = len % 5;

	if (out == NULL) {
		idx = blks * 4;
		if (left_over >= 2)
			idx += left_over - 1;
	}
	else {
		blk_ceiling = blks * 5;
		for (idx = 0, idx2 = 0; idx2 < blk_ceiling; idx += 4, idx2 += 5) {
			// Convert Base85 to 32-bit value
			unsigned long value = 0;
			for (int i = 0; i < 5; i++) {
				value = value * 85 + revchar_base85(in[idx2 + i]);
			}
			
			// Convert to bytes
			out[idx] = (value >> 24) & 0xFF;
			out[idx + 1] = (value >> 16) & 0xFF;
			out[idx + 2] = (value >> 8) & 0xFF;
			out[idx + 3] = value & 0xFF;
		}

		// Handle remaining characters
		if (left_over >= 2) {
			unsigned long value = 0;
			for (int i = 0; i < left_over; i++) {
				value = value * 85 + revchar_base85(in[idx2 + i]);
			}
			
			for (int i = 0; i < left_over - 1; i++) {
				out[idx + i] = (value >> (24 - i * 8)) & 0xFF;
			}
			idx += left_over - 1;
		}
	}

	return(idx);
}

// Randomized Base64 encoding
size_t base64x_random_encode(const BYTE in[], BYTE out[], size_t len, int newline_flag)
{
	size_t idx, idx2, blks, blk_ceiling, left_over, newline_count = 0;

	blks = (len / 3);
	left_over = len % 3;

	if (out == NULL) {
		idx2 = blks * 4;
		if (left_over)
			idx2 += 4;
		if (newline_flag)
			idx2 += len / 57;
	}
	else {
		blk_ceiling = blks * 3;
		for (idx = 0, idx2 = 0; idx < blk_ceiling; idx += 3, idx2 += 4) {
			out[idx2] = base64x_random_charset[in[idx] >> 2];
			out[idx2 + 1] = base64x_random_charset[((in[idx] & 0x03) << 4) | (in[idx + 1] >> 4)];
			out[idx2 + 2] = base64x_random_charset[((in[idx + 1] & 0x0f) << 2) | (in[idx + 2] >> 6)];
			out[idx2 + 3] = base64x_random_charset[in[idx + 2] & 0x3F];
			
			if (((idx2 - newline_count + 4) % NEWLINE_INVL == 0) && newline_flag) {
				out[idx2 + 4] = '\n';
				idx2++;
				newline_count++;
			}
		}

		if (left_over == 1) {
			out[idx2] = base64x_random_charset[in[idx] >> 2];
			out[idx2 + 1] = base64x_random_charset[(in[idx] & 0x03) << 4];
			out[idx2 + 2] = '=';
			out[idx2 + 3] = '=';
			idx2 += 4;
		}
		else if (left_over == 2) {
			out[idx2] = base64x_random_charset[in[idx] >> 2];
			out[idx2 + 1] = base64x_random_charset[((in[idx] & 0x03) << 4) | (in[idx + 1] >> 4)];
			out[idx2 + 2] = base64x_random_charset[(in[idx + 1] & 0x0F) << 2];
			out[idx2 + 3] = '=';
			idx2 += 4;
		}
	}

	return(idx2);
}

// Randomized Base64 decoding
size_t base64x_random_decode(const BYTE in[], BYTE out[], size_t len)
{
	BYTE ch;
	size_t idx, idx2, blks, blk_ceiling, left_over;

	if (in[len - 1] == '=')
		len--;
	if (in[len - 1] == '=')
		len--;

	blks = len / 4;
	left_over = len % 4;

	if (out == NULL) {
		if (len >= 77 && in[NEWLINE_INVL] == '\n')
			len -= len / (NEWLINE_INVL + 1);
		blks = len / 4;
		left_over = len % 4;

		idx = blks * 3;
		if (left_over == 2)
			idx++;
		else if (left_over == 3)
			idx += 2;
	}
	else {
		blk_ceiling = blks * 4;
		for (idx = 0, idx2 = 0; idx2 < blk_ceiling; idx += 3, idx2 += 4) {
			if (in[idx2] == '\n')
				idx2++;
			out[idx] = (revchar_random(in[idx2]) << 2) | ((revchar_random(in[idx2 + 1]) & 0x30) >> 4);
			out[idx + 1] = (revchar_random(in[idx2 + 1]) << 4) | (revchar_random(in[idx2 + 2]) >> 2);
			out[idx + 2] = (revchar_random(in[idx2 + 2]) << 6) | revchar_random(in[idx2 + 3]);
		}

		if (left_over == 2) {
			out[idx] = (revchar_random(in[idx2]) << 2) | ((revchar_random(in[idx2 + 1]) & 0x30) >> 4);
			idx++;
		}
		else if (left_over == 3) {
			out[idx] = (revchar_random(in[idx2]) << 2) | ((revchar_random(in[idx2 + 1]) & 0x30) >> 4);
			out[idx + 1] = (revchar_random(in[idx2 + 1]) << 4) | (revchar_random(in[idx2 + 2]) >> 2);
			idx += 2;
		}
	}

	return(idx);
}
