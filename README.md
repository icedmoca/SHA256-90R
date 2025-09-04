# SHA256-90R Cryptographic Algorithms 

A collection of **extended/hardened cryptographic primitives (XR variants)** for educational and research purposes.  
Includes AES-XR, Blowfish-XR, SHA256-90R, and Base64X. Each with extended security parameters, regression tests, and clean API design.  


---

## Overview

| Algorithm     | Variant    | Rounds | Block / Output Size | Key Features                               | Status |
|---------------|------------|--------|---------------------|--------------------------------------------|--------|
| **AES-XR**    | AES (20R)  | 20     | 128-bit block       | Extended S-boxes, extended key schedule    | ✅ PASS |
| **Blowfish-XR** | Blowfish (32R) | 32 | 64-bit block     | 34 P-keys, regenerated S-boxes             | ✅ PASS |
| **SHA256-90R** | SHA-256 (90R) | 90 | 256-bit hash       | Extended rounds, enhanced compression      | ✅ PASS |
| **Base64X**   | Base64 (X) | –      | Encoded text        | Extended character set, Base85 option      | ✅ PASS |

---

## Details

### 1. AES-XR (20 Rounds)
- 20 rounds (vs 10 for AES-128)  
- Extended S-boxes + key schedule  
- Standard 128-bit block, supports 128/192/256-bit keys  

**Regression Test Vector:**  
```
Plaintext : 6162633132330000 ("abc123")
Ciphertext: 811d512379011df2da935d8964cd59dd
Decrypted : 6162633132330000 ("abc123") ✅ PASS
```

---

### 2. Blowfish-XR (32 Rounds)
- 32 Feistel rounds (vs 16 standard)  
- 34 P-keys, regenerated S-boxes (4 × 256 entries)  
- Standard 64-bit block size  

**Regression Test Vector:**  
```
Plaintext : 7465737464617461 ("testdata")
Ciphertext: c63a9137c6aaa5b8
Decrypted : 7465737464617461 ("testdata") ✅ PASS
```

---

### 3. SHA256-90R
- 90 rounds (vs 64 standard SHA-256)  
- Maintains 256-bit hash output  
- Extended message schedule and compression  

**Example:**  
```
Input : "abc"
Output: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

---

### 4. Base64X
- Extended Base64 variant with custom alphabet / Base85 option  
- Round-trip encoding/decoding supported  
- Fully compatible with standard Base64 decoding  

**Example:**  
```
Input : "foobar"
Output: Zm9vYmFy
```

---

## Test

The project includes a `Makefile` for easy builds.

```bash
# Build and run all tests
make test

# Individual algorithms
make test-aes       # → bin/aes_xr_test
make test-blowfish  # → bin/blowfish_xr_test
make test-sha256    # → bin/sha256_90r_test
make test-base64    # → bin/base64x_test

# Clean artifacts
make clean
```

---

## Disclaimer

> [!WARNING]
> These implementations are *experimental*  educational variants of standard cryptographic primitives (`AES-XR, Blowfish-XR`, `SHA256-90R`, `Base64X`) that logically strengthen security margins by increasing round counts, regenerating S/P-boxes, and diversifying transformations, thereby raising the difficulty of classical cryptanalysis and reducing reliance on standard attack tools; however, they are **not FIPS-validated**, not peer-reviewed, and not hardened against side-channel attacks, so while they may provide meaningful protection in constrained, closed environments (e.g., private research systems, drones, or IoT testbeds), they should not be considered production-secure replacements for vetted, certified cryptographic libraries.


---

## Research Objectives
- [x] Demonstrate the effect of extending cryptographic round counts on algorithmic strength 
- [x] Provide modular reference implementations for comparative analysis 
- [x] Supply regression vectors to facilitate reproducible experiments
- [x] Enable accessible testing via Makefile to support further research
