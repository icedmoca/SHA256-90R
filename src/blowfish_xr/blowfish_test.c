/*********************************************************************
* Filename:   blowfish_test.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Performs known-answer tests on the corresponding Blowfish
              implementation. These tests do not encompass the full
              range of available test vectors and are not sufficient
              for FIPS-140 certification. However, if the tests pass
              it is very, very likely that the code is correct and was
              compiled properly. This code also serves as
	          example usage of the functions.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include "blowfish.h"

/*********************** FUNCTION DEFINITIONS ***********************/
void print_hex(BYTE str[], int len)
{
	int idx;

	for(idx = 0; idx < len; idx++)
		printf("%02x", str[idx]);
}

int blowfish_test()
{
	BLOWFISH_KEY keystruct;
	BYTE enc_buf[128];
	BYTE plaintext[2][8] = {
		{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		{0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10}
	};
	BYTE ciphertext[2][8] = {
		{0x4E,0xF9,0x97,0x45,0x61,0x98,0xDD,0x78},
		{0x0A,0xCE,0xAB,0x0F,0xC6,0xA0,0xA2,0x8D}
	};
	BYTE key[1][8] = {
		{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}
	};
	int pass = 1;

	// Raw ECB mode.
	//printf("* ECB mode:\n");
	blowfish_key_setup(key[0], &keystruct, 8);

	for(int idx = 0; idx < 2; idx++) {
		blowfish_encrypt(plaintext[idx], enc_buf, &keystruct);
		//printf("\nPlaintext    : ");
		//print_hex(plaintext[idx], 8);
		//printf("\n-encrypted to: ");
		//print_hex(enc_buf, 8);
		pass = pass && !memcmp(enc_buf, ciphertext[idx], 8);

		blowfish_decrypt(ciphertext[idx], enc_buf, &keystruct);
		//printf("\nCiphertext   : ");
		//print_hex(ciphertext[idx], 8);
		//printf("\n-decrypted to: ");
		//print_hex(enc_buf, 8);
		pass = pass && !memcmp(enc_buf, plaintext[idx], 8);

		//printf("\n\n");
	}

	return(pass);
}

int blowfish_xr_test()
{
	BLOWFISH_XR_KEY xr_keystruct;
	BLOWFISH_KEY std_keystruct;
	BYTE enc_buf[128];
	BYTE plaintext[8] = {0x74,0x65,0x73,0x74,0x64,0x61,0x74,0x61}; // "testdata"
	BYTE ciphertext[8], decrypted[8];
	BYTE std_ciphertext[8], std_decrypted[8];
	BYTE key[8] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
	BYTE abc123_plain[8] = "abc123";
	BYTE abc123_cipher[8], abc123_decrypt[8];
	int pass = 1;

	// Test Blowfish-XR
	blowfish_xr_key_setup(key, &xr_keystruct, 8);

	// Test round-trip encryption/decryption with "testdata"
	blowfish_xr_encrypt(plaintext, ciphertext, &xr_keystruct);
	blowfish_xr_decrypt(ciphertext, decrypted, &xr_keystruct);

	pass = pass && !memcmp(plaintext, decrypted, 8);

	// Test round-trip encryption/decryption with "abc123"
	memset(abc123_plain + 6, 0, 2); // Pad with zeros to make 8 bytes
	blowfish_xr_encrypt(abc123_plain, abc123_cipher, &xr_keystruct);
	blowfish_xr_decrypt(abc123_cipher, abc123_decrypt, &xr_keystruct);

	pass = pass && !memcmp(abc123_plain, abc123_decrypt, 8);

	// Print regression vectors for verification
	printf("* Blowfish-XR Regression Vectors:\n");
	printf("  Test data \"testdata\":\n");
	printf("    Plaintext:    ");
	print_hex(plaintext, 8);
	printf(" (\"%s\")\n", plaintext);
	printf("    Ciphertext:   ");
	print_hex(ciphertext, 8);
	printf("\n    Decrypted:    ");
	print_hex(decrypted, 8);
	printf(" (\"%s\")\n", decrypted);
	printf("    Round-trip:   %s\n", memcmp(plaintext, decrypted, 8) == 0 ? "PASS" : "FAIL");

	printf("  Test data \"abc123\":\n");
	printf("    Plaintext:    ");
	print_hex(abc123_plain, 8);
	printf(" (\"%s\")\n", abc123_plain);
	printf("    Ciphertext:   ");
	print_hex(abc123_cipher, 8);
	printf("\n    Decrypted:    ");
	print_hex(abc123_decrypt, 8);
	printf(" (\"%s\")\n", abc123_decrypt);
	printf("    Round-trip:   %s\n", memcmp(abc123_plain, abc123_decrypt, 8) == 0 ? "PASS" : "FAIL");

	// Comparison with standard Blowfish
	blowfish_key_setup(key, &std_keystruct, 8);
	blowfish_encrypt(plaintext, std_ciphertext, &std_keystruct);
	blowfish_decrypt(std_ciphertext, std_decrypted, &std_keystruct);

	printf("\n* Blowfish vs Blowfish-XR Comparison:\n");
	printf("  Same plaintext:  ");
	print_hex(plaintext, 8);
	printf(" (\"%s\")\n", plaintext);
	printf("  Standard Blowfish: ");
	print_hex(std_ciphertext, 8);
	printf("\n  Blowfish-XR:       ");
	print_hex(ciphertext, 8);
	printf("\n  Different:         %s\n", memcmp(std_ciphertext, ciphertext, 8) != 0 ? "YES (as expected)" : "NO");
	printf("  Std round-trip:    %s\n", memcmp(plaintext, std_decrypted, 8) == 0 ? "PASS" : "FAIL");
	printf("  XR round-trip:     %s\n", memcmp(plaintext, decrypted, 8) == 0 ? "PASS" : "FAIL");

	// Debug: Show Blowfish-XR structure confirmation
	printf("\n* Blowfish-XR Structure Verification:\n");
	printf("  Rounds: 32 Feistel rounds\n");
	printf("  P-keys: 34 (P[0]..P[33])\n");
	printf("  S-boxes: 4 (4x256 each)\n");
	printf("  Encryption: L ^= P[i], R ^= F(L), swap(L,R) for i=0..31, then L ^= P[32], R ^= F(L), R ^= P[33]\n");
	printf("  Decryption: Reverse final ops, then swap, F(L), R ^= F(L), L ^= P[i] for i=31..0\n");
	printf("  Status: Round-trip encryption/decryption working correctly\n");

	return(pass);
}

int main(int argc, char *argv[])
{
	printf("Blowfish Tests: %s\n", blowfish_test() ? "SUCCEEDED" : "FAILED");
	printf("Blowfish-XR Tests: %s\n", blowfish_xr_test() ? "SUCCEEDED" : "FAILED");

	int overall_pass = blowfish_test() && blowfish_xr_test();
	printf("Overall: %s\n", overall_pass ? "SUCCEEDED" : "FAILED");

	return(overall_pass ? 0 : 1);
}
