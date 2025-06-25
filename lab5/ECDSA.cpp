// Sửa lỗi trong ECDSA.cpp

// OpenSSL library
#include "openssl/evp.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>

// Cryptopp library
#include "cryptopp/files.h"
#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/oids.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/queue.h"
#include "cryptopp/oids.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::ByteQueue;
#include "cryptopp/base64.h"

// C++ library
#include <fstream>
#include <iterator>
#include <vector>
#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;

#include <chrono>
#include <assert.h>
#include <string>
#include <iomanip>
using std::string;

#ifdef _WIN32
#include <windows.h>
#endif

bool GenerateKeys(const char *format, const char *privateKeyFile, const char *publicKeyFile)
{
    string strFormat(format);

    // Khởi tạo OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    // Tạo context cho EC key generation
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) {
        cerr << "Error creating key generation context" << endl;
        return false;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        cerr << "Error initializing key generation" << endl;
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    // Thiết lập curve secp384r1
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1) <= 0) {
        cerr << "Error setting curve" << endl;
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    // Tạo key pair
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        cerr << "Error generating key pair" << endl;
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    bool success = false;
    
    if (strFormat == "BER")
    {
        // Lưu private key ở định dạng BER
        BIO *bioPrivate = BIO_new_file(privateKeyFile, "wb");
        if (bioPrivate && i2d_PrivateKey_bio(bioPrivate, pkey)) {
            BIO_free(bioPrivate);
            
            // Lưu public key ở định dạng BER
            BIO *bioPublic = BIO_new_file(publicKeyFile, "wb");
            if (bioPublic && i2d_PUBKEY_bio(bioPublic, pkey)) {
                BIO_free(bioPublic);
                success = true;
            } else {
                if (bioPublic) BIO_free(bioPublic);
            }
        } else {
            if (bioPrivate) BIO_free(bioPrivate);
        }
    }
    else if (strFormat == "PEM")
    {
        // Lưu private key ở định dạng PEM
        BIO *bioPrivate = BIO_new_file(privateKeyFile, "w");
        if (bioPrivate && PEM_write_bio_PrivateKey(bioPrivate, pkey, NULL, NULL, 0, NULL, NULL)) {
            BIO_free(bioPrivate);
            
            // Lưu public key ở định dạng PEM
            BIO *bioPublic = BIO_new_file(publicKeyFile, "w");
            if (bioPublic && PEM_write_bio_PUBKEY(bioPublic, pkey)) {
                BIO_free(bioPublic);
                success = true;
            } else {
                if (bioPublic) BIO_free(bioPublic);
            }
        } else {
            if (bioPrivate) BIO_free(bioPrivate);
        }
    }

    // Dọn dẹp
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    
    return success;
}

bool sign(const char *privateKeyFile, const char *fileName, const char *signFile)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Đọc private key
    BIO *bio = BIO_new_file(privateKeyFile, "rb");
    if (!bio) {
        cerr << "Error opening private key file: " << privateKeyFile << endl;
        return false;
    }

    string fn = privateKeyFile;
    size_t lastDotPos = fn.find_last_of('.');
    std::string extension = fn.substr(lastDotPos + 1);
    EVP_PKEY *privateKey = nullptr;

    // Load private key dựa trên extension
    if (extension == "pem" || extension == "PEM") {
        privateKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    } else if (extension == "ber" || extension == "BER") {
        privateKey = d2i_PrivateKey_bio(bio, nullptr);
    }
    
    BIO_free(bio);

    if (!privateKey) {
        cerr << "Error loading private key" << endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Đọc file cần ký
    std::ifstream inputFile(fileName, std::ios::binary);
    if (!inputFile.is_open()) {
        cerr << "Error opening input file: " << fileName << endl;
        EVP_PKEY_free(privateKey);
        return false;
    }

    std::vector<unsigned char> fileContents((std::istreambuf_iterator<char>(inputFile)), 
                                           std::istreambuf_iterator<char>());
    inputFile.close();

    if (fileContents.empty()) {
        cerr << "Input file is empty" << endl;
        EVP_PKEY_free(privateKey);
        return false;
    }

    // Tính hash SHA256 của file
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(&fileContents[0], fileContents.size(), hash);

    // Tạo context cho signing
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        cerr << "Error creating MD context" << endl;
        EVP_PKEY_free(privateKey);
        return false;
    }

    // Tạo signature buffer
    size_t signatureLen = EVP_PKEY_size(privateKey);
    std::vector<unsigned char> signature(signatureLen);

    cout << "Starting signing process..." << endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    bool signingSuccess = true;
    
    for (int i = 0; i < 1000 && signingSuccess; ++i) {
        // Reset context cho mỗi lần sign
        if (EVP_DigestSignInit(mdCtx, NULL, EVP_sha256(), NULL, privateKey) != 1) {
            cerr << "Error initializing digest sign" << endl;
            signingSuccess = false;
            break;
        }

        // Update với hash data
        if (EVP_DigestSignUpdate(mdCtx, hash, SHA256_DIGEST_LENGTH) != 1) {
            cerr << "Error updating digest sign" << endl;
            signingSuccess = false;
            break;
        }

        // Finalize signature
        size_t currentSigLen = signatureLen;
        if (EVP_DigestSignFinal(mdCtx, &signature[0], &currentSigLen) != 1) {
            cerr << "Error finalizing signature" << endl;
            signingSuccess = false;
            break;
        }

        // Chỉ ghi file ở lần cuối cùng
        if (i == 999) {
            std::ofstream signatureFile(signFile, std::ios::binary);
            if (!signatureFile.is_open()) {
                cerr << "Error opening signature output file" << endl;
                signingSuccess = false;
                break;
            }
            signatureFile.write(reinterpret_cast<const char *>(&signature[0]), currentSigLen);
            signatureFile.close();
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double averageTime = static_cast<double>(duration) / 1000.0;
    
    if (signingSuccess) {
        std::cout << "Average time for signing over 1000 rounds: " << averageTime << " ms" << std::endl;
    }

    // Dọn dẹp
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(privateKey);
    
    return signingSuccess;
}

bool verify(const char *publicKeyFile, const char *fileName, const char *signFile)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Đọc public key
    BIO *bio = BIO_new_file(publicKeyFile, "rb");
    if (!bio) {
        cerr << "Error opening public key file: " << publicKeyFile << endl;
        return false;
    }

    string fn = publicKeyFile;
    size_t lastDotPos = fn.find_last_of('.');
    std::string extension = fn.substr(lastDotPos + 1);
    EVP_PKEY *publicKey = nullptr;

    // Load public key dựa trên extension
    if (extension == "pem" || extension == "PEM") {
        publicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    } else if (extension == "ber" || extension == "BER") {
        publicKey = d2i_PUBKEY_bio(bio, nullptr);
    }
    
    BIO_free(bio);

    if (!publicKey) {
        cerr << "Error loading public key" << endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Đọc signature file
    std::ifstream signatureFile(signFile, std::ios::binary);
    if (!signatureFile.is_open()) {
        cerr << "Error opening signature file: " << signFile << endl;
        EVP_PKEY_free(publicKey);
        return false;
    }

    std::vector<unsigned char> signature((std::istreambuf_iterator<char>(signatureFile)), 
                                        std::istreambuf_iterator<char>());
    signatureFile.close();

    if (signature.empty()) {
        cerr << "Signature file is empty" << endl;
        EVP_PKEY_free(publicKey);
        return false;
    }

    // Đọc original file
    std::ifstream originalFile(fileName, std::ios::binary);
    if (!originalFile.is_open()) {
        cerr << "Error opening original file: " << fileName << endl;
        EVP_PKEY_free(publicKey);
        return false;
    }

    std::vector<unsigned char> originalContents((std::istreambuf_iterator<char>(originalFile)), 
                                               std::istreambuf_iterator<char>());
    originalFile.close();

    if (originalContents.empty()) {
        cerr << "Original file is empty" << endl;
        EVP_PKEY_free(publicKey);
        return false;
    }

    // Tính hash của original file
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(&originalContents[0], originalContents.size(), hash);

    // Tạo context cho verification
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        cerr << "Error creating MD context" << endl;
        EVP_PKEY_free(publicKey);
        return false;
    }

    cout << "Starting verification process..." << endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    bool verificationSuccess = true;
    
    for (int i = 0; i < 1000 && verificationSuccess; ++i) {
        // Reset context cho mỗi lần verify
        if (EVP_DigestVerifyInit(mdCtx, NULL, EVP_sha256(), NULL, publicKey) != 1) {
            cerr << "Error initializing digest verify" << endl;
            verificationSuccess = false;
            break;
        }

        // Update với hash data
        if (EVP_DigestVerifyUpdate(mdCtx, hash, SHA256_DIGEST_LENGTH) != 1) {
            cerr << "Error updating digest verify" << endl;
            verificationSuccess = false;
            break;
        }

        // Verify signature
        if (EVP_DigestVerifyFinal(mdCtx, &signature[0], signature.size()) != 1) {
            cerr << "Signature verification failed" << endl;
            verificationSuccess = false;
            break;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double averageTime = static_cast<double>(duration) / 1000.0;
    
    if (verificationSuccess) {
        std::cout << "Average time for verifying over 1000 rounds: " << averageTime << " ms" << std::endl;
    }

    // Dọn dẹp
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(publicKey);
    
    return verificationSuccess;
}

int main(int argc, char *argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    
    if (argc < 2) {
        std::cerr << "Usage: \n"
                  << argv[0] << " genkey <format> <privateKeyFile> <publicKeyFile>\n"
                  << argv[0] << " sign <privateKeyFile> <inputFile> <signFile> \n"
                  << argv[0] << " verify <publicKeyFile> <inputFile> <signFile>\n";
        return -1;
    }

    string mode = argv[1];

    if (mode == "genkey" && argc == 5) {
        cout << "Generating key pair..." << endl;
        if (GenerateKeys(argv[2], argv[3], argv[4])) {
            std::cout << "Key generation successful and saved to " << argv[3] << ", " << argv[4] << std::endl;
        } else {
            cout << "Key generation failed!" << std::endl;
            return -1;
        }
    }
    else if (mode == "sign" && argc == 5) {
        if (sign(argv[2], argv[3], argv[4])) {
            std::cout << "Sign successful!" << std::endl;
        } else {
            cout << "Sign failed!" << std::endl;
            return 1;
        }
    }
    else if (mode == "verify" && argc == 5) {
        if (verify(argv[2], argv[3], argv[4])) {
            std::cout << "Verify successful!" << std::endl;
        } else {
            cout << "Verification failed!" << std::endl;
            return 1;
        }
    }
    else {
        cerr << "Invalid arguments. Please check the usage instructions.\n";
        return -1;
    }

    return 0;
}