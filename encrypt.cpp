#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>

#pragma comment(lib, "bcrypt.lib")

// Define NT_SUCCESS macro if not already defined
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Error handling helper function
void HandleError(const std::string& message, NTSTATUS status = 0) {
    std::cerr << "ERROR: " << message;
    if (status != 0) {
        std::cerr << " (NTSTATUS: 0x" << std::hex << status << ")";
    }
    std::cerr << std::endl;
}

// Convert a string to a vector of bytes
std::vector<BYTE> StringToBytes(const std::string& str) {
    return std::vector<BYTE>(str.begin(), str.end());
}

// Simple key derivation function to get a fixed-size key from password and salt
std::vector<BYTE> DeriveKey(const std::string& password, const std::string& salt, size_t keySize) {
    // Combine password and salt
    std::vector<BYTE> material;
    material.insert(material.end(), password.begin(), password.end());
    material.insert(material.end(), salt.begin(), salt.end());
    
    // Create a key of the desired size
    // For real applications, use a proper key derivation function like PBKDF2
    std::vector<BYTE> derivedKey(keySize, 0);
    
    // Simple key stretching - just repeat the material until we fill the key
    // This is NOT secure for production use!
    for (size_t i = 0; i < keySize; i++) {
        derivedKey[i] = material[i % material.size()];
    }
    
    return derivedKey;
}

// Function to encrypt a file using BCrypt
bool EncryptFile(const std::string& inputFilePath, const std::string& password, const std::string& salt) {
    // Derive output file path (input path + .enc)
    std::filesystem::path inPath(inputFilePath);
    std::filesystem::path outPath = inPath;
    outPath.replace_extension(inPath.extension().string() + ".enc");
    
    std::cout << "Input file: " << inputFilePath << std::endl;
    std::cout << "Output file: " << outPath.string() << std::endl;
    
    // Open input file
    std::ifstream inFile(inputFilePath, std::ios::binary);
    if (!inFile) {
        HandleError("Failed to open input file");
        return false;
    }
    
    // Read input file content
    std::vector<BYTE> fileContent((std::istreambuf_iterator<char>(inFile)), 
                                  std::istreambuf_iterator<char>());
    inFile.close();
    
    // Convert salt to byte array
    std::vector<BYTE> saltBytes = StringToBytes(salt);
    
    // BCrypt variables
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = 0;
    DWORD cbData = 0, cbKeyObject = 0, cbBlockLen = 0;
    PBYTE pbKeyObject = NULL;
    
    // Open algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        HandleError("BCryptOpenAlgorithmProvider failed", status);
        return false;
    }
    
    // Set chaining mode to CBC
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, 
                              (PBYTE)BCRYPT_CHAIN_MODE_CBC, 
                              sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status)) {
        HandleError("BCryptSetProperty (chaining mode) failed", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    // Get size of key object
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, 
                              (PBYTE)&cbKeyObject, sizeof(DWORD), 
                              &cbData, 0);
    if (!NT_SUCCESS(status)) {
        HandleError("BCryptGetProperty (object length) failed", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    // Allocate memory for key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) {
        HandleError("Memory allocation for key object failed");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    // Get block length (needed for IV)
    status = BCryptGetProperty(hAlg, BCRYPT_BLOCK_LENGTH, 
                              (PBYTE)&cbBlockLen, sizeof(DWORD), 
                              &cbData, 0);
    if (!NT_SUCCESS(status)) {
        HandleError("BCryptGetProperty (block length) failed", status);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    // Create a key by deriving from password and salt
    // Using a 256-bit (32 byte) key for AES-256
    std::vector<BYTE> keyBytes = DeriveKey(password, salt, 32);
    
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject,
                                      keyBytes.data(), (ULONG)keyBytes.size(), 0);
    if (!NT_SUCCESS(status)) {
        HandleError("BCryptGenerateSymmetricKey failed", status);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    // Create initialization vector (IV) from the salt
    // In production code, you might want a more robust IV generation
    std::vector<BYTE> iv(cbBlockLen, 0);
    for (size_t i = 0; i < saltBytes.size() && i < cbBlockLen; i++) {
        iv[i] = saltBytes[i];
    }
    
    // Determine the size of the encrypted data
    DWORD cbCipherText = 0;
    status = BCryptEncrypt(hKey, fileContent.data(), (ULONG)fileContent.size(),
                          NULL, iv.data(), (ULONG)iv.size(), NULL, 0,
                          &cbCipherText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        HandleError("BCryptEncrypt (size calculation) failed", status);
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    // Allocate memory for the encrypted data
    std::vector<BYTE> cipherText(cbCipherText);
    
    // Perform the encryption
    status = BCryptEncrypt(hKey, fileContent.data(), (ULONG)fileContent.size(),
                          NULL, iv.data(), (ULONG)iv.size(), cipherText.data(), (ULONG)cipherText.size(),
                          &cbData, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        HandleError("BCryptEncrypt failed", status);
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    // Write the IV and encrypted data to the output file
    std::ofstream outFile(outPath.string(), std::ios::binary);
    if (!outFile) {
        HandleError("Failed to create output file");
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    // Write IV size and IV first
    ULONG ivSize = static_cast<ULONG>(iv.size());
    outFile.write(reinterpret_cast<const char*>(&ivSize), sizeof(ivSize));
    outFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    
    // Write encrypted data
    outFile.write(reinterpret_cast<const char*>(cipherText.data()), cipherText.size());
    outFile.close();
    
    // Clean up
    BCryptDestroyKey(hKey);
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    std::cout << "Encryption completed successfully!" << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    // Check command line arguments
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <file_path> <password> <salt>" << std::endl;
        return 1;
    }
    
    std::string filePath = argv[1];
    std::string password = argv[2];
    std::string salt = argv[3];
    
    // Validate inputs
    if (filePath.empty() || password.empty() || salt.empty()) {
        std::cerr << "Error: File path, password, and salt must not be empty." << std::endl;
        return 1;
    }
    
    // Check if input file exists
    if (!std::filesystem::exists(filePath)) {
        std::cerr << "Error: Input file does not exist: " << filePath << std::endl;
        return 1;
    }
    
    // Encrypt the file
    if (!EncryptFile(filePath, password, salt)) {
        std::cerr << "Encryption failed." << std::endl;
        return 1;
    }
    
    return 0;
} 