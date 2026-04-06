# CryptoX 🔐

A high-performance **CLI-based file encryptor** for Windows, built in C using OpenSSL (AES-256-CBC).

CryptoX is designed to **silently and efficiently encrypt files** using multithreading, making it suitable for batch processing and automation workflows where minimal user interaction is required.

---

## ⭐ Support This Project

If you find this project useful, consider giving it a ⭐ on GitHub — it helps others discover it and motivates further development!

---

## ✨ Features

* 🖥️ Command-line (CLI) tool — lightweight and scriptable
* 🤫 **Silent operation** (minimal output unless attached to console)
* 🔒 AES-256-CBC encryption (OpenSSL)
* ⚡ Multithreaded processing (auto scales with CPU cores)
* 📁 Recursive directory scanning
* 📦 Handles large files efficiently
* 🧠 Partial encryption for huge files (improves speed)
* 🧹 Secure file wiping before deletion
* 🔑 Random key generation
* 📄 Tracks encrypted files in `files_list.txt`
* 🔁 Full decryption support

---

## 🛠️ Requirements

* Windows OS
* C compiler (MSVC / MinGW)
* OpenSSL library

---

## 🔧 Build Instructions

### Using MinGW (example):

```bash id="9n1g9k"
gcc cryptox.c -o cryptox.exe -lssl -lcrypto -lws2_32
```

### Using MSVC (example):

```bash id="kqj3vp"
cl cryptox.c /I <openssl_include_path> /link /LIBPATH:<openssl_lib_path> libcrypto.lib libssl.lib
```

---

## 🚀 Usage

```id="jljm3n"
cryptox.exe [options] <path1> [path2] ...
```

### Options

| Option         | Description                                         |
| -------------- | --------------------------------------------------- |
| `-k <hex_key>` | 64 hex characters (32 bytes) AES-256 key            |
| `-o <dir>`     | Output directory for `files_list.txt` and `key.txt` |
| `-g`           | Generate a random key and save it                   |
| `-d <list>`    | Decrypt mode using `files_list.txt`                 |
| `-h`           | Show help                                           |

---

## 🔑 Key Generation

```bash id="0v9m5o"
cryptox.exe -g -o C:\Output
```

---

## 🔒 Encryption

```bash id="2fh2ci"
cryptox.exe -k <your_hex_key> -o C:\Output C:\MyFolder
```

* Files are encrypted silently in the background
* Encrypted files get `.encrypted` extension
* Originals are securely wiped and deleted
* Encrypted file paths are stored in `files_list.txt`

---

## 🔓 Decryption

```bash id="6njc49"
cryptox.exe -d C:\Output\files_list.txt -k <your_hex_key>
```

---

## 🧠 How It Works

* Uses AES-256-CBC with a random IV per file
* IV is stored at the beginning of each encrypted file
* Multithreaded worker system processes files in parallel
* Large files:

  * Only first portion is encrypted (configurable threshold)
  * Remaining data is appended unencrypted for performance

---

## ⚠️ Important Notes

* ⚠️ **KEEP YOUR KEY SAFE** — without it, data cannot be recovered
* ⚠️ Decryption will fail if the wrong key is used
* ⚠️ Original files are permanently deleted after encryption
* ⚠️ Designed for **silent, automated CLI usage**

---

## 📁 Output Files

* `key.txt` → Encryption key (if generated)
* `files_list.txt` → List of encrypted files

---

## 🧪 Example Workflow

```bash id="0c3hqn"
# Generate key
cryptox.exe -g -o C:\Output

# Encrypt files
cryptox.exe -k <key> -o C:\Output C:\MyFolder

# Decrypt later
cryptox.exe -d C:\Output\files_list.txt -k <key>
```

---

## ⚡ Performance

* Uses up to 64 threads (based on CPU cores)
* Processes files in chunks (64 KB)
* Efficient for both small and very large datasets

---

## 📜 License

This project is provided as-is for educational and legitimate use cases.

---

## ⚠️ Disclaimer

This software performs **irreversible file deletion after encryption**.
Use responsibly. The author is not responsible for data loss or misuse.

---
