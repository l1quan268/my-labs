// OpenSSL library

#include "openssl/evp.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h> // Include for SHA256
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
#include <iterator> // Include for std::istreambuf_iterator
#include <vector>   // Include for std::vector
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

// Define DLL export macro
#ifndef DLL_EXPORT
#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport) // define class specifier
#else
#define DLL_EXPORT
#endif
#endif

extern "C"
{
    DLL_EXPORT bool GenerateKeys(const char *format, const char *privateKeyFile, const char *publicKeyFile);
    DLL_EXPORT bool sign(const char *privateKeyFile, const char *fileName, const char *signFile);
    DLL_EXPORT bool verify(const char *publicKeyFile, const char *fileName, const char *signFile);
};

bool GenerateKeys(const char *format, const char *privateKeyFile, const char *publicKeyFile)
{
    string strFormat(format);

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    CryptoPP::AutoSeededRandomPool rng;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(pctx);

    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1);
    EVP_PKEY_keygen(pctx, &pkey);

    // int ec = EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, NULL);
    if (strFormat == "BER")
    {
        // Save private key in BER format
        BIO *bioPrivate = BIO_new_file(privateKeyFile, "wb");
        i2d_PrivateKey_bio(bioPrivate, pkey);
        BIO_free(bioPrivate);
        // Save public key in BER format
        BIO *bioPublic = BIO_new_file(publicKeyFile, "wb");
        i2d_PUBKEY_bio(bioPublic, pkey);
        BIO_free(bioPublic);
        return true;
    }
    else if (strFormat == "PEM")
    {
        BIO *bioPrivate = BIO_new_file(privateKeyFile, "w");
        PEM_write_bio_PrivateKey(bioPrivate, pkey, NULL, NULL, 0, NULL, NULL);
        BIO_free(bioPrivate);
        // Save public key
        BIO *bioPublic = BIO_new_file(publicKeyFile, "w");
        PEM_write_bio_PUBKEY(bioPublic, pkey);
        BIO_free(bioPublic);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return true;
    }
    else
        return false;
}

bool sign(const char *privateKeyFile, const char *fileName, const char *signFile)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    BIO *bio = BIO_new(BIO_s_file());
    BIO_read_filename(bio, privateKeyFile);
    string fn = privateKeyFile;
    size_t lastDotPos = fn.find_last_of('.');
    std::string extension = fn.substr(lastDotPos + 1);
    EVP_PKEY *privateKey = nullptr;
    // Load file private key
    try
    {
        if (extension == "pem" || extension == "PEM")
        {
            privateKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
            BIO_free(bio);
        }
        else if (extension == "ber" || extension == "BER")
        {
            privateKey = d2i_PrivateKey_bio(bio, nullptr);
            BIO_free(bio);
        }
    }
    catch (std::exception &ex)
    {
        return false;
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    // Load file
    try
    {
        std::ifstream pdfFile(fileName, std::ios::binary);
        std::vector<unsigned char> pdfContents((std::istreambuf_iterator<char>(pdfFile)), std::istreambuf_iterator<char>());
        SHA256(&pdfContents[0], pdfContents.size(), hash);
        pdfFile.close();
    }
    catch (std::exception &ex)
    {
        return false;
    }

    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();

    EVP_SignInit(mdCtx, EVP_sha256());
    EVP_SignUpdate(mdCtx, hash, SHA256_DIGEST_LENGTH);

    unsigned int signatureLen = EVP_PKEY_size(privateKey);
    std::vector<unsigned char> signature(signatureLen);

    if (!EVP_SignFinal(mdCtx, &signature[0], &signatureLen, privateKey))
    {
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(privateKey);
        return false;
    }

    std::ofstream signaturefile(signFile, std::ios::binary);
    signaturefile.write(reinterpret_cast<const char *>(&signature[0]), signatureLen);
    signaturefile.close();

    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(privateKey);
    EVP_cleanup();
    ERR_free_strings();
    return true;
}

bool verify(const char *publicKeyFile, const char *fileName, const char *signFile)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    BIO *bio = BIO_new(BIO_s_file());
    BIO_read_filename(bio, publicKeyFile);
    string fn = publicKeyFile;
    size_t lastDotPos = fn.find_last_of('.');
    std::string extension = fn.substr(lastDotPos + 1);
    EVP_PKEY *publicKey = nullptr;
    // Load public key from file
    if (extension == "pem" || extension == "PEM")
    {

        publicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
    }
    else if (extension == "ber" || extension == "BER")
    {
        publicKey = d2i_PUBKEY_bio(bio, nullptr);
        BIO_free(bio);
    }

    if (!publicKey)
    {
        return false;
    }
    std::ifstream signatureFile(signFile, std::ios::binary);
    if (!signatureFile.is_open())
    {
        return false;
    }
    std::vector<unsigned char> signature((std::istreambuf_iterator<char>(signatureFile)), std::istreambuf_iterator<char>());
    signatureFile.close();
    std::ifstream originalFile(fileName, std::ios::binary);
    if (!originalFile.is_open())
    {
        return false;
    }
    std::vector<unsigned char> originalContents((std::istreambuf_iterator<char>(originalFile)), std::istreambuf_iterator<char>());
    originalFile.close();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(&originalContents[0], originalContents.size(), hash);
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    EVP_VerifyInit(mdCtx, EVP_sha256());
    EVP_VerifyUpdate(mdCtx, hash, SHA256_DIGEST_LENGTH);
    if (EVP_VerifyFinal(mdCtx, &signature[0], signature.size(), publicKey) != 1)
    {
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(publicKey);
        return false;
    }
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(publicKey);
    EVP_cleanup();
    ERR_free_strings();
    return true;
}

int main(int argc, char *argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    if (argc < 2)
    {
        std::cerr << "Usage: \n"
                  << argv[0] << " genkey <format> <privateKeyFile> <publicKeyFile>\n"
                  << argv[0] << " sign <privateKeyFile> <inputFile> <signFile> \n"
                  << argv[0] << " decrypt <publicKeyFile> <inputFile> signFile>\n";
        return -1;
    }

    string mode = argv[1];

    if (mode == "genkey" && argc == 5)
    {
        if (GenerateKeys(argv[2], argv[3], argv[4]))
        {
            std::cout << "Key generation successfully and saved to " << argv[3] << ", " << argv[4] << std::endl;
        }
        else
        {
            cout << "Key generation unsuccessfully!" << std::endl;
            return -1;
        }
    }
    else if (mode == "sign" && argc == 5)
    {
        if (sign(argv[2], argv[3], argv[4]))
        {
            std::cout << "Sign successfully!";
        }
        else
        {
            cout << "Sign unsucessfully!";
            return 1;
        }
    }
    else if (mode == "verify" && argc == 5)
    {
        if (verify(argv[2], argv[3], argv[4]))
        {
            std::cout << "Verify successfully!";
        }
        else
        {
            cout << "Sign unsucessfully!";
            return 1;
        }
    }
    else
    {
        cerr << "Invalid arguments. Please check the usage instructions.\n";
        return -1;
    }

    return 0;
}