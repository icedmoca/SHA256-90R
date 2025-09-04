#include <stdio.h>
#include <string.h>
#include "aes.h"

void print_hex(BYTE str[], int len) {
    for(int idx = 0; idx < len; idx++)
        printf("%02x", str[idx]);
}

int main() {
    BYTE key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    BYTE plaintext[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                          0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    BYTE ciphertext[16], decrypted[16];
    WORD key_schedule[120];

    printf("=== AES-XR Round-Trip Test ===\n");

    // Setup key
    aes_xr_key_setup(key, key_schedule, 128);

    // Encrypt
    aes_xr_encrypt(plaintext, ciphertext, key_schedule, 128);
    printf("Plaintext:  ");
    print_hex(plaintext, 16);
    printf("\n");
    printf("Ciphertext: ");
    print_hex(ciphertext, 16);
    printf("\n");

    // Decrypt
    aes_xr_decrypt(ciphertext, decrypted, key_schedule, 128);
    printf("Decrypted:  ");
    print_hex(decrypted, 16);
    printf("\n");

    // Check if round-trip works
    int match = memcmp(plaintext, decrypted, 16) == 0;
    printf("Round-trip: %s\n", match ? "SUCCESS" : "FAILED");

    // Test with "abc123" as requested
    printf("\n=== AES-XR 'abc123' Test ===\n");
    BYTE test_plain[16] = "abc123";
    BYTE test_cipher[16], test_decrypt[16];
    memset(test_plain + 6, 0, 10); // Pad with zeros

    aes_xr_encrypt(test_plain, test_cipher, key_schedule, 128);
    aes_xr_decrypt(test_cipher, test_decrypt, key_schedule, 128);

    printf("Plaintext:  ");
    print_hex(test_plain, 16);
    printf(" (\"%s\")\n", test_plain);
    printf("Ciphertext: ");
    print_hex(test_cipher, 16);
    printf("\n");
    printf("Decrypted:  ");
    print_hex(test_decrypt, 16);
    printf(" (\"%s\")\n", test_decrypt);

    int test_match = memcmp(test_plain, test_decrypt, 16) == 0;
    printf("Round-trip: %s\n", test_match ? "SUCCESS" : "FAILED");

    return (match && test_match) ? 0 : 1;
}
