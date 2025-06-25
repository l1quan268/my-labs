#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "cryptopp/sha.h"
#include "cryptopp/sha3.h"
#include "cryptopp/shake.h"
using CryptoPP::SHA1;
using CryptoPP::SHA256;

#include "cryptopp/filters.h"
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::DecodingResult;
using CryptoPP::Exception;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

#include <stdexcept>
using std::runtime_error;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::ifstream;

#include <assert.h>
#include <fstream>

// Vietnamese on Windows
#include <chrono>
#ifdef _WIN32
#include <windows.h>
#endif
#include <locale>
#include <cstdlib>
#include <cctype>

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
    DLL_EXPORT const char *hashFunction(const char *algo, const char *inputMes, int length);
};

const char *hashFunction(const char *algo, const char *inputMes, int length)
{
    std::unique_ptr<CryptoPP::HashTransformation> hash;
    string strAlgo(algo);

    if (strAlgo == "SHA3_224")
    {
        hash.reset(new CryptoPP::SHA3_224);
    }
    else if (strAlgo == "SHA3_256")
    {
        hash.reset(new CryptoPP::SHA3_256);
    }
    else if (strAlgo == "SHA3_384")
    {
        hash.reset(new CryptoPP::SHA3_384);
    }
    else if (strAlgo == "SHA3_512")
    {
        hash.reset(new CryptoPP::SHA3_512);
    }
    else if (strAlgo == "SHA224")
    {
        hash.reset(new CryptoPP::SHA224);
    }
    else if (strAlgo == "SHA256")
    {
        hash.reset(new CryptoPP::SHA256);
    }
    else if (strAlgo == "SHA384")
    {
        hash.reset(new CryptoPP::SHA384);
    }
    else if (strAlgo == "SHA512")
    {
        hash.reset(new CryptoPP::SHA512);
    }
    else if (strAlgo == "SHAKE128")
    {
        hash.reset(new CryptoPP::SHAKE128);
    }
    else if (strAlgo == "SHAKE256")
    {
        hash.reset(new CryptoPP::SHAKE256);
    }
    else
    {
        std::cerr << "Invalid hash type: " << strAlgo << std::endl;
        exit(1);
    }

    std::cout << "Name: " << hash->AlgorithmName() << std::endl;
    std::cout << "Digest size: " << hash->DigestSize() << std::endl;
    std::cout << "Block size: " << hash->BlockSize() << std::endl;
    HexEncoder encoder(new FileSink(std::cout));

    // Open File and get message
    string message(inputMes);

    std::string digest;

    // hashing
    hash->Update((const CryptoPP::byte *)message.data(), message.size());
    if (strAlgo == "SHAKE128" || strAlgo == "SHAKE256")
    {
        digest.resize(length);
        hash->TruncatedFinal((CryptoPP::byte *)&digest[0], length); // compute ouput
    }
    else
    {
        digest.resize(hash->DigestSize());
        hash->Final((CryptoPP::byte *)&digest[0]);
    }

    cout << "Digest: ";
    string encoded;
    StringSource(digest, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded)));
    std::cout << encoded << std::endl;
    const char *result;
    result = encoded.c_str();
    return result;
}
/*
int main(int argc, char *argv[])
{
#ifdef __linux__
    std::locale::global(std::locale("C.utf8"));
#endif

#ifdef _WIN32
    // Set console code page to UTF-8 on Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    if (argc == 3)
    {
        cout << hashFunction(argv[1], argv[2], 0);
    }
    else if (argc == 4)
    {
        int SHAKElength = std::stoi(argv[3]);
        cout << hashFunction(argv[1], argv[2], SHAKElength);
    }
    else
    {
        std::cerr << "Usage: " << argv[0] << " <hash_type> <message> <length>" << std::endl;
        std::cerr << "Hash types: SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256" << std::endl
                  << "If hash algo is SHAKE128 or SHAKE256, please type length" << std::endl;
        return 1;
    }
}
    */
