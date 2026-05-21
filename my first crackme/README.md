# my first crackme 

crackme: https://crackmes.one/crackme/69ce60243e328e778db052cd

---

## Binary Overview

| Field | Value |
|-------|-------|
| **File Name** | SillyCrackMe.exe |
| **Architecture** | x86-64 (PE) |
| **Language** | Rust |
| **Base Address** | 0x140000000 |
| **Image Size** | 0x3C000 |
| **MD5** | 3b9fc64e11ea7a4468b57adacbd328ca |
| **SHA256** | 940dc3c0a2924a335a404fbbc4c816b99e1feadcac3b1d3ebaf8e4f1a0953a9c |
| **Total Functions** | 663 |
| **Total Strings** | 381 |

## Dependencies & Crates

The binary was compiled with the following Rust crates (identified via leaked build paths in the `.rdata` section):

| Crate | Version | Purpose |
|-------|---------|---------|
| `obfstr` | 0.4.4 | Compile-time string obfuscation using XOR + SplitMix64 PRNG |
| `md5` | 0.8.0 | MD5 hash computation |
| `rustc-demangle` | 0.1.26 | Symbol demangling (standard Rust runtime) |

Build environment: `stable-x86_64-pc-windows-msvc` toolchain, user `Core i5`.

## Segments

| Segment | Start | End | Size | Permissions |
|---------|-------|-----|------|-------------|
| `.text` | 0x140001000 | 0x14002B000 | 0x2A000 | r-x |
| `.idata` | 0x14002B000 | 0x14002B2D0 | 0x2D0 | r-- |
| `.rdata` | 0x14002B2D0 | 0x140038000 | 0xCD30 | r-- |
| `.data` | 0x140038000 | 0x140039000 | 0x1000 | rw- |
| `.pdata` | 0x140039000 | 0x14003B000 | 0x2000 | r-- |

## Entry Points

| Address | Name | Description |
|---------|------|-------------|
| 0x140029170 | `start` | PE entry point → CRT initialization |
| 0x1400170A0 | `TlsCallback_0` | TLS callback for thread-local cleanup |

## Execution Flow

```
start (0x140029170)
  └─► __scrt_common_main_seh
        └─► main (0x14000E630)
              └─► lang_start(rust_main, argc, argv, 0)
                    └─► rust_main (0x140007850)  ← core crackme logic
```

### main (0x14000E630)

```c
int main(int argc, char **argv, char **envp) {
    return lang_start(rust_main, argc, argv, 0);
}
```

A thin wrapper that passes the actual Rust main function pointer (`0x140007850`) to `std::rt::lang_start`.

### rust_main (0x140007850)

- **Size**: 27,982 bytes
- **Basic Blocks**: 1,138
- **Cyclomatic Complexity**: 72

This function contains the entire crackme logic. It is massively inflated due to `obfstr` inlining XOR deobfuscation code for every encrypted string. The function:

1. Deobfuscates and prints a prompt string to the console
2. Reads a line of user input from stdin
3. Computes the MD5 hash of the input
4. Converts the 16-byte hash digest to a 32-character lowercase hex string
5. Compares the hex string against a hardcoded target hash
6. Prints a success or failure message based on the comparison result

## String Obfuscation (obfstr)

All user-facing strings (prompt, success message, failure message) are encrypted at compile time using the `obfstr` crate. The obfuscation uses:

### SplitMix64 PRNG Constants

```
0x9E3779B97F4A7C15   (golden ratio × 2^64)
0xBF58476D1CE4E5B9   (mix constant 1)
0x94D049BB133111EB   (mix constant 2)
```

### Per-Character Operation Selection

Each character is deobfuscated through a switch statement with 8 cases:

| Case | Operation |
|------|-----------|
| 0 | `result = hi32 + accumulator` |
| 1 | `result = hi32 - accumulator` |
| 2 | `result = hi32 ^ accumulator` |
| 3 | `result = random() ^ accumulator` |
| 4 | `result = ~accumulator` |
| 5 | `result = (acc >> shift) ^ acc` |
| 6 | `result = hi32 * accumulator` |
| 7 | `result = -accumulator` |

The repeated "switch 8 cases" blocks visible in IDA's comments throughout `rust_main` correspond to individual character decryptions.

## Password Validation Logic

### Hardcoded MD5 Hash

The target hash is stored as a plaintext ASCII string at `0x14002CAE8`:

```
73acd9a5972130b75066c82595a1fae3
```

This string is **not** obfuscated by obfstr — it is likely constructed at runtime from the hex encoding of the MD5 digest, then compared directly.

### Comparison Function (0x140001580)

```c
bool string_not_equal(__int64 a1, __int64 a2) {
    void *Buf1 = *(void **)(a1 + 8);     // ptr to user's MD5 hex string
    size_t len  = *(_QWORD *)(a1 + 16);  // length (32)

    // Rust &str comparison:
    bool match = (len == *(QWORD*)(a2 + 8))            // length check
              && (memcmp(Buf1, *(void**)a2, len) == 0); // byte-by-byte check

    return !match;  // true if NOT equal
}
```

This implements Rust's `!=` operator for `&str`. It compares:
- `a1` → the MD5 hex digest of user input (32 bytes)
- `a2` → the hardcoded hash `73acd9a5972130b75066c82595a1fae3` (32 bytes)

### Flow After Comparison

- If `memcmp` returns 0 (strings match) → success branch → deobfuscates and prints success message
- If `memcmp` returns non-zero → failure branch → deobfuscates and prints failure message

## Key Functions Summary

| Address | Size | Name/Role | Description |
|---------|------|-----------|-------------|
| 0x14000E630 | 31 B | `main` | C main, calls lang_start |
| 0x140007850 | 27,982 B | `rust_main` | Core crackme logic |
| 0x140001580 | 293 B | `string_compare` | memcmp-based &str comparison |
| 0x1400068E0 | — | `md5_compute` | MD5 hash computation |
| 0x14000EC30 | — | `print_prompt` | Console output (obfstr decryption + println) |
| 0x14000ECE0 | — | `read_input` | stdin read_line |
| 0x140012A90 | 36 B | `rdtsc_wrapper` | RDTSC-based value (used in obfstr PRNG seeding) |
| 0x1400170A0 | 296 B | `TlsCallback_0` | Thread-local storage cleanup |

## Notable Imports

| Import | Module | Relevance |
|--------|--------|-----------|
| `ReadConsoleW` | KERNEL32 | Reading user input |
| `WriteConsoleW` | KERNEL32 | Printing prompt/result messages |
| `GetStdHandle` | KERNEL32 | Obtaining stdin/stdout handles |
| `memcmp` | VCRUNTIME140 | String comparison in validation |
| `memcpy` | VCRUNTIME140 | Buffer operations |
| `IsDebuggerPresent` | KERNEL32 | Anti-debug (standard CRT, not actively used) |

## Solution

### Password

```
ADMIN
```

### Verification

```bash
$ echo -n "ADMIN" | md5sum
73acd9a5972130b75066c82595a1fae3  -
```

The MD5 hash of the string `ADMIN` matches the hardcoded target hash exactly.

### Pseudocode of the Crackme Logic

```rust
fn main() {
    let prompt = obfstr::obfstr!("Enter password: ");
    print!("{}", prompt);

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();

    let digest = md5::compute(input);
    let hash_hex = format!("{:x}", digest);

    let target = "73acd9a5972130b75066c82595a1fae3";

    if hash_hex == target {
        let success = obfstr::obfstr!("Correct! Well done!");
        println!("{}", success);
    } else {
        let failure = obfstr::obfstr!("Wrong password! Try again.");
        println!("{}", failure);
    }
}
```

## Methodology

1. **Static Triage**: Identified language (Rust), crates (obfstr, md5), and binary metadata via string analysis
2. **Entry Point Tracing**: Followed `start` → CRT → `main` → `lang_start` → `rust_main`
3. **Function Analysis**: Examined `rust_main` callees and string references rather than reading the full 28KB decompilation
4. **Hash Extraction**: Located the plaintext MD5 hash `73acd9a5972130b75066c82595a1fae3` at `0x14002CAE8`
5. **Comparison Logic**: Identified `sub_140001580` as the comparison function using `memcmp`
6. **Hash Cracking**: Reversed the MD5 hash via rainbow table lookup → `ADMIN`
