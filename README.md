# DISCRET

A simple command-line tool to **encrypt and decrypt files using AES-256-CBC**, built in C with the help of **OpenSSL**. This utility uses secure password-based key derivation (PBKDF2 with SHA-256) and is designed to protect your files with strong cryptographic practices.

---

## Features

-  AES-256-CBC encryption
-  Random salt and IV generation
-  Password-based key derivation using PBKDF2 (600,000 iterations, SHA-256)
-  File input/output support
-  Uses OpenSSL for cryptographic operations


---

## build

```bash
g++ main.cpp -o discret -lcrypto -lssl
```

---

## Usage

```bash
./discret <encrypt|decrypt> <password> <input_file> <output_file>
