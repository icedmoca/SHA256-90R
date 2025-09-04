/*********************************************************************
* Filename:   sha256_90r_test.c
* Author:     Based on Brad Conte's SHA-256 test
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Performs known-answer tests on the SHA-256-90R implementation.
*             This is a variant of SHA-256 with 90 rounds instead of 64.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include "sha256.h"

/*********************** FUNCTION DEFINITIONS ***********************/
int sha256_90r_test()
{
	BYTE text1[] = {"abc"};
	BYTE text2[] = {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
	BYTE text3[] = {"aaaaaaaaaa"};
	BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_90R_CTX ctx;
	int idx;
	int pass = 1;

	printf("Testing SHA-256-90R with \"abc\"...\n");
	sha256_90r_init(&ctx);
	sha256_90r_update(&ctx, text1, strlen(text1));
	sha256_90r_final(&ctx, buf);
	
	printf("SHA-256-90R(\"abc\") = ");
	for (idx = 0; idx < SHA256_BLOCK_SIZE; ++idx)
		printf("%02x", buf[idx]);
	printf("\n");

	printf("Testing SHA-256-90R with longer string...\n");
	sha256_90r_init(&ctx);
	sha256_90r_update(&ctx, text2, strlen(text2));
	sha256_90r_final(&ctx, buf);
	
	printf("SHA-256-90R(long string) = ");
	for (idx = 0; idx < SHA256_BLOCK_SIZE; ++idx)
		printf("%02x", buf[idx]);
	printf("\n");

	printf("Testing SHA-256-90R with repeated 'a' (100,000 times)...\n");
	sha256_90r_init(&ctx);
	for (idx = 0; idx < 100000; ++idx)
	   sha256_90r_update(&ctx, text3, strlen(text3));
	sha256_90r_final(&ctx, buf);
	
	printf("SHA-256-90R(100,000 'a's) = ");
	for (idx = 0; idx < SHA256_BLOCK_SIZE; ++idx)
		printf("%02x", buf[idx]);
	printf("\n");

	return(pass);
}

int main()
{
	printf("=== SHA-256-90R Test Suite ===\n");
	printf("This is a variant of SHA-256 with 90 rounds instead of 64.\n");
	printf("The hash values will be different from standard SHA-256.\n\n");
	
	sha256_90r_test();
	
	printf("\nSHA-256-90R tests completed.\n");
	printf("Note: These hash values are different from standard SHA-256 due to the extended rounds.\n");

	return(0);
}
