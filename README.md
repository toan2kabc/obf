# QUOCTOANDEV – Advanced Code & Data Protection Framework

A lightweight, header‑only C++ library that combines **compile‑time** and **runtime** obfuscation techniques to protect sensitive constants, strings, control flow, and function pointers from static analysis and reverse engineering.

## Features

- **Compile‑time constant encryption** – Automatically encrypts string literals and static arrays using a multi‑layer cipher (XOR, rotation, addition). The decryption occurs at runtime, leaving only encrypted data in the binary.
- **Runtime string protection** – Dynamically encrypt/decrypt strings with a rolling key, reducing the window of plaintext exposure in memory.
- **MBA (Mixed Boolean‑Arithmetic) obfuscation** – Transforms common arithmetic and logical operations into obfuscated equivalents (addition, subtraction, multiplication, XOR, AND, OR).
- **Function pointer indirection** – Protects indirect calls by storing pointers in a table and using a key‑mangled index.
- **Integrity checking** – Calculates and verifies CRC‑like checksums to detect tampering of critical data or code sections.
- **Cross‑platform** – Works on Windows (MSVC) and Linux/macOS/Android (GCC/Clang). Supports 32‑bit and 64‑bit environments.

## Quick Start

1. Include the header in your source file:
   ```cpp
   #include "QUOCTOANDEV.h"
