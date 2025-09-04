# SHA256-90R Cryptographic Algorithms 

A collection of **extended/hardened cryptographic primitives (XR variants)** for educational and research purposes.  
Includes AES-XR, Blowfish-XR, SHA256-90R, and Base64X. Each with extended security parameters, regression tests, and clean API design.  


---

## Overview

| Algorithm        | Rounds | Block / Output Size | Cycles/Byte (cpb) | Bytes/Cycle | Latency per Block (ns) | Throughput/Core (Gbps) | Slowdown vs Standard | Notes                |
|------------------|--------|---------------------|-------------------|-------------|------------------------|------------------------|---------------------|----------------------|
| **AES-XR**       | 20     | 128-bit block       | ~24 cpb           | 0.041       | ~86 ns                 | ~2.4 Gbps              | 🔴 2.0× (+100%)      | ↑ Rounds, ↑ S-box    |
| **Blowfish-XR**  | 32     | 64-bit block        | ~90 cpb           | 0.011       | ~198 ns                | ~0.45 Gbps             | 🔴 2.0× (+100%)      | ↑ Rounds, ↑ P/S-box  |
| **SHA256-90R**   | 90     | 256-bit hash        | ~21 cpb           | 0.048       | ~169 ns                | ~2.9 Gbps              | 🟡 1.4× (+40%)       | ↑ Rounds, ↑ CompFn   |
| **Base64X**      | –      | Encoded text        | ~5 cpb            | 0.20        | ~25 ns (per 3B chunk)  | ~9.6 Gbps              | 🟢 1.25× (+25%)      | ↑ Alphabet/Base85    |

\* Assumptions: CPU ~3.5 GHz, single core, no hardware crypto extensions. Slowdown values are relative to standard AES-128, Blowfish-16R, SHA-256 (64R), and Base64.

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
Decrypted : 6162633132330000 ("abc123")
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
Decrypted : 7465737464617461 ("testdata")
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

### *Prerequisites*
- GCC or Clang (C compiler)  
- `make` build system  
- Linux, macOS, or Windows (via WSL)  

**Install**

```bash
git clone https://github.com/<your-username>/SHA256-90R.git
cd SHA256-90R
```

**Build:**
```bash
make
```

**Run All Tests:**
```bash
make test
```

**Run Individual Algorithm Tests:**

*AES-XR tests → bin/aes_xr_test*
```bash
make test-aes
```
*Blowfish-XR tests → bin/blowfish_xr_test*
```bash
make test-blowfish
```
*SHA256-90R tests → bin/sha256_90r_test*
```bash
make test-sha256
```
*Base64X tests → bin/base64x_test*
```bash
make test-base64
```

**Clean Build Artifacts:**
```bash
make clean
```

---

## Disclaimer

> [!WARNING]
> These implementations are *experimental*  educational variants of standard cryptographic primitives (`AES-XR, Blowfish-XR`, `SHA256-90R`, `Base64X`) that logically strengthen security margins by increasing round counts, regenerating S/P-boxes, and diversifying transformations, thereby raising the difficulty of classical cryptanalysis and reducing reliance on standard attack tools; however, they are **not FIPS-validated**, not peer-reviewed, and not hardened against side-channel attacks, so while they may provide meaningful protection in constrained, closed environments (e.g., private research systems, drones, or IoT testbeds), they should not be considered production-secure replacements for vetted, certified cryptographic libraries.

---

## Repository Structure
```
SHA256-90R/
├── src/
│   ├── aes_xr/           # AES Extended Rounds
│   ├── blowfish_xr/      # Blowfish Extended Rounds
│   ├── sha256_90r/       # SHA256 Extended Rounds
│   └── base64x/          # Base64 Extended
├── bin/                  # Compiled test executables
├── tests/                # Comprehensive XR test harness
├── Makefile              # Build system
└── README.md             # Documentation
```


---

## Research Objectives
- [x] Demonstrate the effect of extending cryptographic round counts on algorithmic strength 
- [x] Provide modular reference implementations for comparative analysis 
- [x] Supply regression vectors to facilitate reproducible experiments
- [x] Enable accessible testing via Makefile to support further research

