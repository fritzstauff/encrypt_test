# File Encryption Tool

A Windows-based file encryption and decryption tool using the Windows Cryptography API (BCrypt).

## Requirements

- Windows operating system
- Visual Studio or other C++ compiler that supports C++17
- Windows SDK (for bcrypt.h and bcrypt.lib)

## Building the Application

You can build the application using Visual Studio:

1. Open Visual Studio
2. Create a new C++ Console Application project
3. Add the `encrypt.cpp` and `decrypt.cpp` files to your project
4. Make sure to link against `bcrypt.lib` (this is done via the `#pragma comment(lib, "bcrypt.lib")` directive in the code)
5. Build the project

Alternatively, you can build from the command line using the MSVC compiler:

```
cl /EHsc /std:c++17 encrypt.cpp /link bcrypt.lib
cl /EHsc /std:c++17 decrypt.cpp /link bcrypt.lib
```

## Usage

### Encrypting a File

```
encrypt.exe <file_path> <password> <salt>
```

Parameters:
- `file_path`: Path to the file you want to encrypt
- `password`: The password to use for encryption
- `salt`: The salt value to use (enhances security)

The encrypted file will be created with the same name as the original file but with an additional `.enc` extension.

### Decrypting a File

```
decrypt.exe <encrypted_file_path> <password> <salt>
```

Parameters:
- `encrypted_file_path`: Path to the encrypted file (must have .enc extension)
- `password`: The same password used for encryption
- `salt`: The same salt value used for encryption

The decrypted file will be created with the original filename plus "_decrypted" appended before the extension.

## Security Notes

- The password and salt are used to derive a 256-bit AES key
- The implementation uses a simple key derivation function that combines the password and salt
- The salt is also used to derive the initialization vector (IV)
- This implementation uses AES encryption with CBC mode
- For production use, consider implementing a stronger key derivation function (like PBKDF2)
- Store your password and salt securely - if you lose them, you won't be able to decrypt your files

## Example

```
encrypt.exe C:\Documents\secret.docx MySecurePassword MySalt123
```

This will create `C:\Documents\secret.docx.enc`

```
decrypt.exe C:\Documents\secret.docx.enc MySecurePassword MySalt123
```

This will create `C:\Documents\secret_decrypted.docx`

## Limitations

- This is a basic implementation and may not be suitable for highly sensitive data
- The key derivation function is very simple and not cryptographically strong
- No password strength validation is performed
- The same salt is used for all files, which reduces security (ideally, a random salt should be generated for each file)
- Error handling is basic and may not provide detailed information about all failure modes 