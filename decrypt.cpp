#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>

#pragma comment(lib, "bcrypt.lib")

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

// Function to decrypt a file using BCrypt
bool DecryptFile(const std::string& inputFilePath, const std::string& password, const std::string& salt) {
    // Derive output file path (remove .enc extension)
    std::filesystem::path inPath(inputFilePath);
    std::filesystem::path outPath = inPath;
    std::string ext = inPath.extension().string();
    
    // Ensure the file has .enc extension
    if (ext != ".enc") {
        HandleError("Input file must have .enc extension");
        return false;
    }
    
    // Remove .enc extension to get original extension
    std::string originalExt = inPath.stem().extension().string();
    std::string baseName = inPath.stem().stem().string();
    outPath = inPath.parent_path() / (baseName + "_decrypted" + originalExt);
    
    std::cout << "Input file: " << inputFilePath << std::endl;
    std::cout << "Output file: " << outPath.string() << std::endl;
    
    // Open input file
    std::ifstream inFile(inputFilePath, std::ios::binary);
    if (!inFile) {
        HandleError("Failed to open input file");
        return false;
    }
    
    // Read IV size
    ULONG ivSize = 0;
    inFile.read(reinterpret_cast<char*>(&ivSize), sizeof(ivSize));
    if (!inFile) {
        HandleError("Failed to read IV size from file");
        return false;
    }
    
    // Read IV
    std::vector<BYTE> iv(ivSize);
    inFile.read(reinterpret_cast<char*>(iv.data()), ivSize);
    if (!inFile) {
        HandleError("Failed to read IV from file");
        return false;
    }
    
    // Read encrypted data
    std::vector<BYTE> encryptedData((std::istreambuf_iterator<char>(inFile)), 
                                    std::istreambuf_iterator<char>());
    inFile.close();
    
    // Convert password to byte array
    std::vector<BYTE> passwordBytes = StringToBytes(password);
    
    // BCrypt variables
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = 0;
    DWORD cbData = 0, cbKeyObject = 0;
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
    
    // Create a key from the password
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject,
                                       (PBYTE)passwordBytes.data(), (ULONG)passwordBytes.size(), 0);
    if (!NT_SUCCESS(status)) {
        HandleError("BCryptGenerateSymmetricKey failed", status);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    // Determine the size of the decrypted data
    DWORD cbPlainText = 0;
    status = BCryptDecrypt(hKey, encryptedData.data(), (ULONG)encryptedData.size(),
                          NULL, iv.data(), (ULONG)iv.size(), NULL, 0,
                          &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        HandleError("BCryptDecrypt (size calculation) failed", status);
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    // Allocate memory for the decrypted data
    std::vector<BYTE> plainText(cbPlainText);
    
    // Perform the decryption
    status = BCryptDecrypt(hKey, encryptedData.data(), (ULONG)encryptedData.size(),
                          NULL, iv.data(), (ULONG)iv.size(), plainText.data(), (ULONG)plainText.size(),
                          &cbData, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        HandleError("BCryptDecrypt failed", status);
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    // Write the decrypted data to the output file
    std::ofstream outFile(outPath.string(), std::ios::binary);
    if (!outFile) {
        HandleError("Failed to create output file");
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    outFile.write(reinterpret_cast<const char*>(plainText.data()), plainText.size());
    outFile.close();
    
    // Clean up
    BCryptDestroyKey(hKey);
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    std::cout << "Decryption completed successfully!" << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    // Check command line arguments
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <encrypted_file_path> <password> <salt>" << std::endl;
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
    
    // Decrypt the file
    if (!DecryptFile(filePath, password, salt)) {
        std::cerr << "Decryption failed." << std::endl;
        return 1;
    }
    
    return 0;
} 