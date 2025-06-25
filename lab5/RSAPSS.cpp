#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#include <fstream>
#include <vector>
#include <iostream>
#include <string>
#include <iterator>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace std;

bool GenerateKeys(const char *format, const char *privateKeyFile, const char *publicKeyFile, const int keysize)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    string strFormat(format);
    
    // Sử dụng EVP API thay vì RSA API deprecated
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    
    if (!pctx) {
        cerr << "Failed to create RSA key generation context." << endl;
        return false;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        cerr << "Failed to initialize RSA key generation." << endl;
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, keysize) <= 0) {
        cerr << "Failed to set RSA key size." << endl;
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        cerr << "Failed to generate RSA key pair." << endl;
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    bool success = false;

    if (strFormat == "BER") {
        // Save private key in BER format
        BIO *bioPrivate = BIO_new_file(privateKeyFile, "wb");
        if (bioPrivate && i2d_PrivateKey_bio(bioPrivate, pkey)) {
            BIO_free(bioPrivate);
            
            // Save public key in BER format
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
    else if (strFormat == "PEM") {
        // Save private key in PEM format
        BIO *bioPrivate = BIO_new_file(privateKeyFile, "w");
        if (bioPrivate && PEM_write_bio_PrivateKey(bioPrivate, pkey, NULL, NULL, 0, NULL, NULL)) {
            BIO_free(bioPrivate);
            
            // Save public key in PEM format
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
    else {
        cerr << "Unknown format specified. Use PEM or BER." << endl;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return success;
}

int sign(const char *privateKeyFile, const char *filename, const char *signFile)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Determine file format from extension
    string fn = privateKeyFile;
    size_t lastDotPos = fn.find_last_of('.');
    string extension = (lastDotPos != string::npos) ? fn.substr(lastDotPos + 1) : "";

    BIO *bio = BIO_new_file(privateKeyFile, "rb");
    if (!bio) {
        cerr << "Failed to open private key file: " << privateKeyFile << endl;
        return 1;
    }

    EVP_PKEY *pkey = nullptr;
    if (extension == "pem" || extension == "PEM") {
        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    } else if (extension == "ber" || extension == "BER") {
        pkey = d2i_PrivateKey_bio(bio, NULL);
    } else {
        // Try PEM first, then BER
        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        if (!pkey) {
            BIO_reset(bio);
            pkey = d2i_PrivateKey_bio(bio, NULL);
        }
    }

    BIO_free(bio);

    if (!pkey) {
        cerr << "Failed to read private key." << endl;
        ERR_print_errors_fp(stderr);
        return 2;
    }

    // Read file to sign
    ifstream inFile(filename, ios::binary);
    if (!inFile.is_open()) {
        cerr << "Failed to open input file: " << filename << endl;
        EVP_PKEY_free(pkey);
        return 3;
    }

    vector<unsigned char> fileContents((istreambuf_iterator<char>(inFile)), istreambuf_iterator<char>());
    inFile.close();

    if (fileContents.empty()) {
        cerr << "Input file is empty." << endl;
        EVP_PKEY_free(pkey);
        return 3;
    }

    // Calculate SHA256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(&fileContents[0], fileContents.size(), hash);

    // Create signing context
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        cerr << "Failed to create MD context." << endl;
        EVP_PKEY_free(pkey);
        return 4;
    }

    EVP_PKEY_CTX *pkeyCtx = NULL;

    if (EVP_DigestSignInit(mdCtx, &pkeyCtx, EVP_sha256(), NULL, pkey) <= 0) {
        cerr << "Failed to initialize signing context." << endl;
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return 4;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING) <= 0) {
        cerr << "Failed to set RSA PSS padding." << endl;
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return 5;
    }

    if (EVP_DigestSignUpdate(mdCtx, hash, SHA256_DIGEST_LENGTH) <= 0) {
        cerr << "Failed to update signing context." << endl;
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return 6;
    }

    size_t sigLen = 0;
    if (EVP_DigestSignFinal(mdCtx, NULL, &sigLen) <= 0) {
        cerr << "Failed to get signature length." << endl;
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return 7;
    }

    vector<unsigned char> signature(sigLen);
    if (EVP_DigestSignFinal(mdCtx, signature.data(), &sigLen) <= 0) {
        cerr << "Failed to generate signature." << endl;
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return 8;
    }

    // Write signature to file
    ofstream outFile(signFile, ios::binary);
    if (!outFile.is_open()) {
        cerr << "Failed to open signature output file: " << signFile << endl;
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return 9;
    }

    outFile.write(reinterpret_cast<const char *>(signature.data()), sigLen);
    outFile.close();

    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(pkey);
    return 0;
}

int verify(const char *publicKeyFile, const char *filename, const char *signFile)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Determine file format from extension
    string fn = publicKeyFile;
    size_t lastDotPos = fn.find_last_of('.');
    string extension = (lastDotPos != string::npos) ? fn.substr(lastDotPos + 1) : "";

    BIO *bio = BIO_new_file(publicKeyFile, "rb");
    if (!bio) {
        cerr << "Failed to open public key file: " << publicKeyFile << endl;
        return 1;
    }

    EVP_PKEY *pkey = nullptr;
    if (extension == "pem" || extension == "PEM") {
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    } else if (extension == "ber" || extension == "BER") {
        pkey = d2i_PUBKEY_bio(bio, NULL);
    } else {
        // Try PEM first, then BER
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        if (!pkey) {
            BIO_reset(bio);
            pkey = d2i_PUBKEY_bio(bio, NULL);
        }
    }

    BIO_free(bio);

    if (!pkey) {
        cerr << "Failed to read public key." << endl;
        ERR_print_errors_fp(stderr);
        return 2;
    }

    // Read original file
    ifstream inFile(filename, ios::binary);
    if (!inFile.is_open()) {
        cerr << "Failed to open input file: " << filename << endl;
        EVP_PKEY_free(pkey);
        return 3;
    }

    vector<unsigned char> fileContents((istreambuf_iterator<char>(inFile)), istreambuf_iterator<char>());
    inFile.close();

    if (fileContents.empty()) {
        cerr << "Input file is empty." << endl;
        EVP_PKEY_free(pkey);
        return 3;
    }

    // Calculate SHA256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(&fileContents[0], fileContents.size(), hash);

    // Read signature file
    ifstream sigFile(signFile, ios::binary);
    if (!sigFile.is_open()) {
        cerr << "Failed to open signature file: " << signFile << endl;
        EVP_PKEY_free(pkey);
        return 7;
    }

    vector<unsigned char> signature((istreambuf_iterator<char>(sigFile)), istreambuf_iterator<char>());
    sigFile.close();

    if (signature.empty()) {
        cerr << "Signature file is empty." << endl;
        EVP_PKEY_free(pkey);
        return 7;
    }

    // Create verification context
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        cerr << "Failed to create MD context." << endl;
        EVP_PKEY_free(pkey);
        return 4;
    }

    EVP_PKEY_CTX *pkeyCtx = NULL;

    if (EVP_DigestVerifyInit(mdCtx, &pkeyCtx, EVP_sha256(), NULL, pkey) <= 0) {
        cerr << "Failed to initialize verification context." << endl;
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return 4;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING) <= 0) {
        cerr << "Failed to set RSA PSS padding." << endl;
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return 5;
    }

    if (EVP_DigestVerifyUpdate(mdCtx, hash, SHA256_DIGEST_LENGTH) <= 0) {
        cerr << "Failed to update verification context." << endl;
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return 6;
    }

    int verifyResult = EVP_DigestVerifyFinal(mdCtx, signature.data(), signature.size());
    
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(pkey);

    if (verifyResult != 1) {
        return 8;
    }

    return 0;
}

int main(int argc, char *argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    if (argc < 2) {
        std::cerr << "Usage: \n"
                  << argv[0] << " genkey <format> <privateKeyFile> <publicKeyFile> <keySize>\n"
                  << argv[0] << " sign <privateKeyFile> <inputFile> <signFile> \n"
                  << argv[0] << " verify <publicKeyFile> <inputFile> <signFile>\n";
        return -1;
    }

    string mode = argv[1];

    if (mode == "genkey" && argc == 6) {
        cout << "Generating RSA key pair..." << endl;
        if (GenerateKeys(argv[2], argv[3], argv[4], stoi(argv[5]))) {
            cout << "Key generation successful and saved to " << argv[3] << ", " << argv[4] << endl;
        } else {
            cerr << "Key generation failed." << endl;
            return -1;
        }
    }
    else if (mode == "sign" && argc == 5) {
        cout << "Starting RSA-PSS signing process..." << endl;
        
        int result = -1;
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < 1000; i++) {
            result = sign(argv[2], argv[3], argv[4]);
            if (result != 0) {
                cerr << "Signing failed on iteration " << i + 1 << " with error code: " << result << endl;
                break;
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        
        if (result == 0) {
            std::cout << "Average time for signing over 1000 rounds: " << averageTime << " ms" << std::endl;
            cout << "Sign file successfully!" << endl;
        } else {
            cout << "Sign file unsuccessfully! Error code: " << result << endl;
            return -1;
        }
    }
    else if (mode == "verify" && argc == 5) {
        cout << "Starting RSA-PSS verification process..." << endl;
        
        int result = -1;
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < 1000; i++) {
            result = verify(argv[2], argv[3], argv[4]);
            if (result != 0) {
                cerr << "Verification failed on iteration " << i + 1 << " with error code: " << result << endl;
                break;
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        
        if (result == 0) {
            std::cout << "Average time for verifying over 1000 rounds: " << averageTime << " ms" << std::endl;
            cout << "Verify file successfully!" << endl;
        } else {
            cerr << "Verify file unsuccessfully! Error code: " << result << endl;
            return -1;
        }
    }
    else {
        cerr << "Invalid arguments. Please check the usage instructions." << endl;
        return -1;
    }

    return 0;
}