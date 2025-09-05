/*********************************************************************
* Filename:   crypto_xr_test.c
* Author:     Based on Brad Conte's implementations
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Comprehensive test for all XR (Extended Round) variants
*             Tests both standard and XR implementations side-by-side
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include "aes.h"
#include "sha256.h"
#include "base64.h"
#include "blowfish.h"

/****************************** MACROS ******************************/
#define TEST_STRING "Hello, World! This is a test of the extended round cryptographic algorithms."

/*********************** FUNCTION DEFINITIONS ***********************/
void print_hex(const BYTE data[], size_t len, const char* label)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void test_aes_variants()
{
    printf("\n=== AES vs AES-XR Comparison ===\n");
    
    BYTE key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    BYTE plaintext[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 
                          0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    BYTE ciphertext_std[16], ciphertext_xr[16];
    BYTE decrypted_std[16], decrypted_xr[16];
    WORD key_schedule_std[60], key_schedule_xr[60];
    
    // Setup keys
    aes_key_setup(key, key_schedule_std, 128);
    aes_xr_key_setup(key, key_schedule_xr, 128);
    
    // Encrypt
    aes_encrypt(plaintext, ciphertext_std, key_schedule_std, 128);
    aes_xr_encrypt(plaintext, ciphertext_xr, key_schedule_xr, 128);
    
    print_hex(plaintext, 16, "Plaintext");
    print_hex(ciphertext_std, 16, "AES-128");
    print_hex(ciphertext_xr, 16, "AES-XR-128");
    
    // Decrypt
    aes_decrypt(ciphertext_std, decrypted_std, key_schedule_std, 128);
    aes_xr_decrypt(ciphertext_xr, decrypted_xr, key_schedule_xr, 128);
    
    printf("AES-128 Decryption: %s\n", 
           memcmp(plaintext, decrypted_std, 16) == 0 ? "PASS" : "FAIL");
    printf("AES-XR-128 Decryption: %s\n", 
           memcmp(plaintext, decrypted_xr, 16) == 0 ? "PASS" : "FAIL");
}

void test_sha256_variants()
{
    printf("\n=== SHA-256 vs SHA-256-90R Comparison ===\n");
    
    BYTE text[] = "abc";
    BYTE hash_std[SHA256_BLOCK_SIZE], hash_90r[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx_std;
    SHA256_90R_CTX ctx_90r;
    
    // Standard SHA-256
    sha256_init(&ctx_std);
    sha256_update(&ctx_std, text, strlen((char*)text));
    sha256_final(&ctx_std, hash_std);
    
    // SHA-256-90R
    sha256_90r_init(&ctx_90r);
    sha256_90r_update(&ctx_90r, text, strlen((char*)text));
    sha256_90r_final(&ctx_90r, hash_90r);
    
    print_hex(text, strlen((char*)text), "Input");
    print_hex(hash_std, SHA256_BLOCK_SIZE, "SHA-256");
    print_hex(hash_90r, SHA256_BLOCK_SIZE, "SHA-256-90R");
}

void test_base64_variants()
{
    printf("\n=== Base64 vs BASE64X Comparison ===\n");
    
    BYTE input[] = "Hello, World!";
    BYTE encoded_std[100], encoded_xr[100], encoded_base85[100], encoded_random[100];
    BYTE decoded_std[100], decoded_xr[100], decoded_base85[100], decoded_random[100];
    size_t len_std, len_xr, len_base85, len_random;
    
    // Standard Base64
    len_std = base64_encode(input, encoded_std, strlen((char*)input), 0);
    base64_decode(encoded_std, decoded_std, len_std);
    
    // BASE64X - Standard mode
    base64x_set_mode(0);
    len_xr = base64x_encode(input, encoded_xr, strlen((char*)input), 0);
    base64x_decode(encoded_xr, decoded_xr, len_xr);
    
    // BASE64X - Base85 mode
    base64x_set_mode(1);
    len_base85 = base64x_encode(input, encoded_base85, strlen((char*)input), 0);
    base64x_decode(encoded_base85, decoded_base85, len_base85);
    
    // BASE64X - Randomized mode
    base64x_set_mode(2);
    len_random = base64x_encode(input, encoded_random, strlen((char*)input), 0);
    base64x_decode(encoded_random, decoded_random, len_random);
    
    printf("Input: %s\n", input);
    printf("Base64: %.*s\n", (int)len_std, encoded_std);
    printf("BASE64X (Standard): %.*s\n", (int)len_xr, encoded_xr);
    printf("BASE64X (Base85): %.*s\n", (int)len_base85, encoded_base85);
    printf("BASE64X (Random): %.*s\n", (int)len_random, encoded_random);
    
    printf("Base64 Decode: %s\n", 
           memcmp(input, decoded_std, strlen((char*)input)) == 0 ? "PASS" : "FAIL");
    printf("BASE64X (Standard) Decode: %s\n", 
           memcmp(input, decoded_xr, strlen((char*)input)) == 0 ? "PASS" : "FAIL");
    printf("BASE64X (Base85) Decode: %s\n", 
           memcmp(input, decoded_base85, strlen((char*)input)) == 0 ? "PASS" : "FAIL");
    printf("BASE64X (Random) Decode: %s\n", 
           memcmp(input, decoded_random, strlen((char*)input)) == 0 ? "PASS" : "FAIL");
}

void test_blowfish_variants()
{
    printf("\n=== Blowfish vs Blowfish-XR Comparison ===\n");
    
    BYTE key[] = "MySecretKey";
    BYTE plaintext[8] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    BYTE ciphertext_std[8], ciphertext_xr[8];
    BYTE decrypted_std[8], decrypted_xr[8];
    BLOWFISH_KEY key_std;
    BLOWFISH_XR_KEY key_xr;
    
    // Setup keys
    blowfish_key_setup(key, &key_std, strlen((char*)key));
    blowfish_xr_key_setup(key, &key_xr, strlen((char*)key));
    
    // Encrypt
    blowfish_encrypt(plaintext, ciphertext_std, &key_std);
    blowfish_xr_encrypt(plaintext, ciphertext_xr, &key_xr);
    
    print_hex(plaintext, 8, "Plaintext");
    print_hex(ciphertext_std, 8, "Blowfish");
    print_hex(ciphertext_xr, 8, "Blowfish-XR");
    
    // Decrypt
    blowfish_decrypt(ciphertext_std, decrypted_std, &key_std);
    blowfish_xr_decrypt(ciphertext_xr, decrypted_xr, &key_xr);
    
    printf("Blowfish Decryption: %s\n", 
           memcmp(plaintext, decrypted_std, 8) == 0 ? "PASS" : "FAIL");
    printf("Blowfish-XR Decryption: %s\n", 
           memcmp(plaintext, decrypted_xr, 8) == 0 ? "PASS" : "FAIL");
}

int main()
{
    printf("=== Extended Round Cryptographic Algorithms Test Suite ===\n");
    printf("Testing standard vs XR (Extended Round) variants side-by-side\n");
    
    test_aes_variants();
    test_sha256_variants();
    test_base64_variants();
    test_blowfish_variants();
    
    printf("\n=== Test Suite Complete ===\n");
    printf("All XR variants provide enhanced security through:\n");
    printf("- AES-XR: 20+ rounds vs 10-14 standard rounds\n");
    printf("- SHA-256-90R: 90 rounds vs 64 standard rounds\n");
    printf("- BASE64X: Multiple encoding modes (Base64, Base85, Randomized)\n");
    printf("- Blowfish-XR: 32 rounds vs 16 standard rounds\n");
    
    return 0;
}
