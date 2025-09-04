/*********************************************************************
* Filename:   sha256_comparison_test.c
* Author:     Based on Brad Conte's SHA-256 test
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Compares SHA-256 and SHA-256-90R outputs for the same input.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include "sha256.h"

int main()
{
	BYTE text[] = {"abc"};
	BYTE hash_standard[SHA256_BLOCK_SIZE];
	BYTE hash_90r[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx_standard;
	SHA256_90R_CTX ctx_90r;
	int i;

	printf("=== SHA-256 vs SHA-256-90R Comparison ===\n");
	printf("Input: \"abc\"\n\n");

	// Standard SHA-256
	sha256_init(&ctx_standard);
	sha256_update(&ctx_standard, text, strlen(text));
	sha256_final(&ctx_standard, hash_standard);

	// SHA-256-90R
	sha256_90r_init(&ctx_90r);
	sha256_90r_update(&ctx_90r, text, strlen(text));
	sha256_90r_final(&ctx_90r, hash_90r);

	printf("SHA-256:     ");
	for (i = 0; i < SHA256_BLOCK_SIZE; ++i)
		printf("%02x", hash_standard[i]);
	printf("\n");

	printf("SHA-256-90R: ");
	for (i = 0; i < SHA256_BLOCK_SIZE; ++i)
		printf("%02x", hash_90r[i]);
	printf("\n\n");

	printf("The hashes are different because SHA-256-90R uses 90 rounds\n");
	printf("instead of the standard 64 rounds, making it a different hash function.\n");

	return(0);
}
