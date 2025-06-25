// C++ standard
#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;
#include <fstream>

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <cstdlib>
#include <locale>
#include <cctype>
#include <chrono>

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/nbtheory.h"
using CryptoPP::ModularSquareRoot;

#include "cryptopp/modarith.h"
using CryptoPP::ModularArithmetic;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/filters.h"
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;

#include "cryptopp/dsa.h"
using CryptoPP::DSA;

// #include "cryptopp/pem.h"
// using CryptoPP::PEM_Load;
// using CryptoPP::PEM_Save;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

// Set up Vietnamese
//  header part
#ifdef _WIN32
#include <windows.h>
#endif
string encoded, decoded, plain, cipher, recover;

// Define DLL export macro
// #ifndef DLL_EXPORT
// #ifdef _WIN32
// #define DLL_EXPORT __declspec(dllexport) // define class specifier
// #else
// #define DLL_EXPORT
// #endif
// #endif

// Save key function
void Save(const string &filename, const BufferedTransformation &bt);
void SavePrivateKey(const string &filename, const PrivateKey &key);
void SavePublicKey(const string &filename, const PublicKey &key);

void SaveBase64(const string &filename, const BufferedTransformation &bt);
void SaveBase64PrivateKey(const string &filename, const PrivateKey &key);
void SaveBase64PublicKey(const string &filename, const PublicKey &key);

// Load key
void Load(const string &filename, BufferedTransformation &bt);
void LoadPrivateKey(const string &filename, PrivateKey &key);
void LoadPublicKey(const string &filename, PublicKey &key);

void LoadBase64(const string &filename, BufferedTransformation &bt);
void LoadBase64PrivateKey(const string &filename, PrivateKey &key);
void LoadBase64PublicKey(const string &filename, PublicKey &key);

void EncodePublicKey(const string &filename, const RSA::PublicKey &key);
void EncodePrivateKey(const string &filename, const RSA::PrivateKey &key);
void Encode(const string &filename, const BufferedTransformation &bt);

void DecodePrivateKey(const string &filename, RSA::PrivateKey &key);
void DecodePublicKey(const string &filename, RSA::PublicKey &key);
void Decode(const string &filename, BufferedTransformation &bt);

// Key gen
void GenerateAndSaveRSAKeys(int keySize, const char *format, const char *privateKeyFile, const char *publicKeyFile)
{

    string strFormat(format);
    string strPrivateKeyFile(privateKeyFile);
    string strPublicKeyFile(publicKeyFile);

    FileSink filePrivate(privateKeyFile, true);
    FileSink filePublic(publicKeyFile, true);

    AutoSeededRandomPool rnd;

    RSA::PrivateKey rsaPrivate;
    rsaPrivate.GenerateRandomWithKeySize(rnd, keySize);
    RSA::PublicKey rsaPublic(rsaPrivate);

    if (strFormat == "BER")
    {
        EncodePrivateKey(strPrivateKeyFile, rsaPrivate);
        EncodePublicKey(strPublicKeyFile, rsaPublic);
        cout << "Successfully generated and saved RSA keys BER" << endl;
    }
    else if (strFormat == "PEM")
    {
        // PEM_Save(filePrivate, rsaPrivate);
        // PEM_Save(filePublic, rsaPublic);
        cout << "Successfully generated and saved RSA keys PEM" << endl;
    }
    else if (strFormat == "Base64")
    {
        SaveBase64PrivateKey(strPrivateKeyFile, rsaPrivate);
        SaveBase64PublicKey(strPublicKeyFile, rsaPublic);
    }
    else
    {
        cout << "Unsupported Format. Please choose 'BER' or 'PEM' or 'Base64' " << endl;
        exit(1);
    }

    Integer modul = rsaPrivate.GetModulus();      // modul n (from private)
    Integer prime1 = rsaPrivate.GetPrime1();      // prime p
    Integer prime2 = rsaPrivate.GetPrime2();      // prime q
    Integer SK = rsaPrivate.GetPrivateExponent(); // secret exponent d;

    Integer PK = rsaPublic.GetPublicExponent(); // public exponent e;
    Integer modul2 = rsaPublic.GetModulus();    // modul n

    cout << "Modulo (private) n = " << modul << endl;
    cout << "Modulo (public) n = " << modul2 << endl;
    cout << "Prime number p =  " << std::hex << prime1 << std::dec << endl;
    cout << "Prime number q =  " << std::hex << prime2 << std::dec << endl;
    cout << "Secret exponent d = " << SK << endl;
    cout << "Public exponent e = " << PK << endl; // 17

    RSA::PrivateKey r1, r2;
    r1.GenerateRandomWithKeySize(rnd, 3072);

    SavePrivateKey("rsa-roundtrip.key", r1);
    LoadPrivateKey("rsa-roundtrip.key", r2);

    r1.Validate(rnd, 3);
    r2.Validate(rnd, 3);

    if (r1.GetModulus() != r2.GetModulus() ||
        r1.GetPublicExponent() != r2.GetPublicExponent() ||
        r1.GetPrivateExponent() != r2.GetPrivateExponent())
    {
        throw runtime_error("key data did not round trip");
    }

    cout << "Successfully generated and saved RSA keys" << endl;
}

// Ecrypt
void RSAencrypt(const char *format, const char *publicKeyFile,
                const char *cipherTextFormat,
                const char *PlainTextFile, const char *CipherTextFile)
{
    AutoSeededRandomPool rng;
    string strFormat(format);
    string strPublicKeyFile(publicKeyFile);
    string strCipherTextFormat(cipherTextFormat);

    RSA::PublicKey publicKey;

    // Load key from file
    if (strFormat == "BER")
    {
        cout << "You choose BER - Encryption!" << endl;
        DecodePublicKey(strPublicKeyFile, publicKey);
    }
    else if (strFormat == "PEM")
    {
        cout << "You choose PEM - Encryption!" << endl;
        FileSource filePublic(publicKeyFile, true);
        // PEM_Load(filePublic, publicKey); // bỏ vì không dùng PEM
    }
    else if (strFormat == "Base64")
    {
        cout << "You choose Base64 - Encryption!" << endl;
        LoadBase64PublicKey(strPublicKeyFile, publicKey);
    }
    else
    {
        cout << "Unsupported Format. Please choose 'BER' or 'PEM' or 'Base64' " << endl;
        exit(1);
    }

    // 🔄 Load plain text and truncate to avoid RSA limit
    plain.clear();
    FileSource file(PlainTextFile, true, new StringSink(plain));
    if (plain.size() > 300)
        plain = plain.substr(0, 300); // Cắt đúng 300 byte

    // Encrypt & benchmark
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < 10000; ++i)
    {
        cipher.clear();
        RSAES_OAEP_SHA_Encryptor e(publicKey);
        StringSource(plain, true, new PK_EncryptorFilter(rng, e, new StringSink(cipher)));
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double averageTime = static_cast<double>(duration) / 10000.0;
    std::cout << "Average time for encryption over 10000 rounds: " << averageTime << " ms" << std::endl;

    // Output ciphertext in specified format
    encoded.clear();
    if (strCipherTextFormat == "Hex")
    {
        cout << "Cipher text will be displayed in Hex format" << endl;
        StringSource(cipher, true, new HexEncoder(new StringSink(encoded), false));
    }
    else if (strCipherTextFormat == "Base64")
    {
        cout << "Cipher text will be displayed in Base64 format" << endl;
        StringSource(cipher, true, new Base64Encoder(new StringSink(encoded), false));
    }

    // Save cipher text to file
    StringSource(encoded, true, new FileSink(CipherTextFile));
}


void RSAdecrypt(const char *format, const char *privateKeyFile,
                const char *cipherTextFormat,
                const char *CipherText, const char *RecoverText)
{
    AutoSeededRandomPool rng;
    string strFormat(format);
    string strPrivateKeyFile(privateKeyFile);
    string strCipherTextFormat(cipherTextFormat);

    RSA::PrivateKey privateKey;

    // Load key from file
    if (strFormat == "BER")
    {
        cout << "You choose BER - Encryption!" << endl;
        DecodePrivateKey(strPrivateKeyFile, privateKey);
    }
    else if (strFormat == "PEM")
    {
        cout << "You choose PEM - Encryption!" << endl;
        FileSource filePrivate(privateKeyFile, true);
        // PEM_Load(filePrivate, privateKey);
    }
    else if (strFormat == "Base64")
    {
        cout << "You choose BER - Encryption!" << endl;
        LoadBase64PrivateKey(strPrivateKeyFile, privateKey);
    }
    else
    {
        cout << "Unsupported Format. Please choose 'BER' or 'PEM' or 'Base64' " << endl;
        exit(1);
    }
    // Load cipher text from file
    FileSource(CipherText, true, new StringSink(cipher));

    decoded.clear();
    // Decode cipher text
    if (strCipherTextFormat == "Hex")
    {
        StringSource(cipher, true, new HexDecoder(new StringSink(decoded)));
    }
    else if (strCipherTextFormat == "Base64")
    {
        StringSource(cipher, true, new Base64Decoder(new StringSink(decoded)));
    }
    // Decrypt
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < 10000; ++i)
    {
        // Encryption logic here
        RSAES_OAEP_SHA_Decryptor d(privateKey);
        StringSource(decoded, true, new PK_DecryptorFilter(rng, d, new StringSink(recover)));
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double averageTime = static_cast<double>(duration) / 10000.0;
    std::cout << "Average time for encryption over 10000 rounds: " << averageTime << " ms" << std::endl;
    // Save recover text
    StringSource(recover, true, new FileSink(((RecoverText))));
}

int main(int argc, char **argv)
{
// Set locale to support UTF-8
#ifdef __linux__
    std::locale::global(std::locale("C.utf8"));
#endif

#ifdef _WIN32
    // Set console code page to UTF-8 on Windows C.utf8, CP_UTF8
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    std::ios_base::sync_with_stdio(false);

    if (argc < 2)
    {
        cerr << "Usage: \n"
             << argv[0] << " genkey <keysize> <format> <privateKeyFile> <publicKeyFile>\n"
             << argv[0] << " encrypt <format> <publicKeyFile> <cipherFormat> <plaintextFile> <cipherFile>\n"
             << argv[0] << " decrypt <format> <privateKeyFile> <cipherFormat> <cipherFile> <recoverTextFile>\n";
        return -1;
    }

    string mode = argv[1];

    if (mode == "genkey" && argc == 6)
    {
        cout << argv[2];
        int keySize = std::stoi(argv[2]);
        cout << keySize;
        GenerateAndSaveRSAKeys(keySize, argv[3], argv[4], argv[5]);
    }
    else if (mode == "encrypt" && (argc == 7))
    {
        RSAencrypt(argv[2], argv[3], argv[4], argv[5], argv[6]);
    }
    else if (mode == "decrypt" && (argc == 7))
    {
        RSAdecrypt(argv[2], argv[3], argv[4], argv[5], argv[6]);
    }
    else
    {
        cerr << "Invalid arguments. Please check the usage instructions.\n";
        return -1;
    }

    return 0;
}

// DEF FUNCTION
void SavePrivateKey(const string &filename, const PrivateKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
}

void SavePublicKey(const string &filename, const PublicKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
}

void Save(const string &filename, const BufferedTransformation &bt)
{
    FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}

void SaveBase64PrivateKey(const string &filename, const PrivateKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    SaveBase64(filename, queue);
}

void SaveBase64PublicKey(const string &filename, const PublicKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    SaveBase64(filename, queue);
}

void SaveBase64(const string &filename, const BufferedTransformation &bt)
{
    Base64Encoder encoder;
    bt.CopyTo(encoder);
    encoder.MessageEnd();
    Save(filename, encoder);
}

void LoadPrivateKey(const string &filename, PrivateKey &key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void LoadPublicKey(const string &filename, PublicKey &key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void Load(const string &filename, BufferedTransformation &bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);
    file.TransferTo(bt);
    bt.MessageEnd();
}

void LoadBase64PrivateKey(const string &filename, PrivateKey &key)
{
    CryptoPP::FileSource file(filename.c_str(), true, new CryptoPP::Base64Decoder);
    CryptoPP::ByteQueue queue;
    file.TransferTo(queue);
    queue.MessageEnd();
    key.Load(queue);
    CryptoPP::AutoSeededRandomPool prng;
    if (!key.Validate(prng, 3))
    {
        throw std::runtime_error("Loaded private key is invalid.");
    }
}

void LoadBase64PublicKey(const string &filename, PublicKey &key)
{
    CryptoPP::FileSource file(filename.c_str(), true, new CryptoPP::Base64Decoder);
    CryptoPP::ByteQueue queue;
    file.TransferTo(queue);
    queue.MessageEnd();
    key.Load(queue);
    CryptoPP::AutoSeededRandomPool prng;
    if (!key.Validate(prng, 3))
    {
        throw std::runtime_error("Loaded public key is invalid.");
    }
}

void EncodePrivateKey(const string &filename, const RSA::PrivateKey &key)
{
    ByteQueue queue;
    key.DEREncodePrivateKey(queue);
    Encode(filename, queue);
}

void EncodePublicKey(const string &filename, const RSA::PublicKey &key)
{
    ByteQueue queue;
    key.DEREncodePublicKey(queue);
    Encode(filename, queue);
}

void Encode(const string &filename, const BufferedTransformation &bt)
{
    FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}

void DecodePrivateKey(const string &filename, RSA::PrivateKey &key)
{
    ByteQueue queue;
    Decode(filename, queue);
    key.BERDecodePrivateKey(queue, false /*optParams*/, queue.MaxRetrievable());
}

void DecodePublicKey(const string &filename, RSA::PublicKey &key)
{
    ByteQueue queue;
    Decode(filename, queue);
    key.BERDecodePublicKey(queue, false /*optParams*/, queue.MaxRetrievable());
}

void Decode(const string &filename, BufferedTransformation &bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);
    file.TransferTo(bt);
    bt.MessageEnd();
}
