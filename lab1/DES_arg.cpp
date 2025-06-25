#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;

#include "assert.h"

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::AuthenticatedSymmetricCipher;
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::ArraySource;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::Redirector;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include "cryptopp/ccm.h"
using CryptoPP::CTR_Mode;

#include "cryptopp/xts.h"
using CryptoPP::XTS;

#include <cryptopp/ccm.h>
using CryptoPP::CCM;
#include "cryptopp/gcm.h"
using CryptoPP::GCM;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/des.h>
using CryptoPP::DES;

#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::ArraySource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;

#ifdef _WIN32
#include <windows.h>
#endif

using namespace std;
using namespace CryptoPP;

string hexdecode(CryptoPP::byte encoded[], unsigned int size);
string hexencode(CryptoPP::byte decoded[], unsigned int size);
string base64decode(CryptoPP::byte encoded[], unsigned int size);
string base64encode(CryptoPP::byte decoded[], unsigned int size);
string hexdecode(string encoded);
string hexencode(string decoded);
string base64decode(string encoded);
string base64encode(string decoded);

void GenerateKeyAndIV(const char *mode, int keySize, const char *format, const char *keyFile, const char *ivFile)
{
    string strMode(mode);
    string strFormat(format);
    string strKeyFile(keyFile);
    string strIVFile(ivFile);
    string encoded;

    AutoSeededRandomPool prng;
    int ivSize = 16;
    CryptoPP::byte *iv = new CryptoPP::byte[ivSize];
    CryptoPP::byte *key = new CryptoPP::byte[keySize];

    prng.GenerateBlock(key, keySize);
    cout << "Generate key successfully!" << endl;

    if (strMode != "ECB")
    {
        prng.GenerateBlock(iv, ivSize);
        cout << "Generate IV successfully!" << endl;
    }
    if (strFormat == "Binary")
    {
        StringSource(key, true, new FileSink(keyFile, keySize));
        cout << "Key saved in Binary format in file " << keyFile << endl;
        if (strMode != "ECB")
        {
            StringSource(iv, true, new FileSink(ivFile, ivSize));
            cout << "IV saved in Binary format in file " << ivFile << endl;
        }
    }
    else if (strFormat == "Hex")
    {
        encoded = hexencode(key, keySize);
        StringSource(encoded, true, new FileSink(keyFile, keySize));
        cout << "Key saved in Hex format in file " << keyFile << endl;
        if (strMode != "ECB")
        {
            encoded = hexencode(iv, ivSize);
            StringSource(encoded, true, new FileSink(ivFile, ivSize));
            cout << "IV saved in Binary format in file " << ivFile << endl;
        }
    }
    else if (strFormat == "Base64")
    {
        encoded = base64encode(key, keySize);
        StringSource(encoded, true, new FileSink(keyFile, keySize));
        cout << "Key saved in Base64 format in file " << keyFile << endl;
        if (strMode != "ECB")
        {
            encoded = base64encode(iv, ivSize);
            StringSource(encoded, true, new FileSink(ivFile, ivSize));
            cout << "IV saved in Binary format in file " << ivFile << endl;
        }
    }
    else
    {
        exit(1);
    }
}

void DESEncrypt(const char *mode, const char *keyIVFormat, const char *keyFile, const char *ivFile,
                const char *cipherFormat,
                const char *plainTextFile, const char *cipherTextFile)
{
    string dataKey, dataIV, decodedKey, decodedIV, plain, cipher, encoded;
    string strMode(mode);
    string strFormat(keyIVFormat);
    string strCFormat(cipherFormat);

    // Load key and IV from file
    FileSource(keyFile, true, new StringSink(dataKey));
    if (strMode != "ECB")
        FileSource(ivFile, true, new StringSink(dataIV));
    if (strFormat == "Binary")
    {
        decodedKey = dataKey;
        if (strMode != "ECB")
            decodedIV = dataIV;
    }
    else if (strFormat == "Hex")
    {
        decodedKey = hexdecode(dataKey);
        if (strMode != "ECB")
            decodedIV = hexdecode(dataIV);
    }
    else if (strFormat == "Base64")
    {
        decodedKey = base64decode(dataKey);
        if (strMode != "ECB")
            decodedIV = base64decode(dataIV);
    }
    else
    {
        exit(1);
    }

    int ivSize = 16;
    CryptoPP::byte *iv = new CryptoPP::byte[ivSize];
    CryptoPP::byte *key = new CryptoPP::byte[decodedKey.length()];
    int keySize = decodedKey.length();

    StringSource(decodedKey, true, new ArraySink(key, keySize));
    StringSource(decodedIV, true, new ArraySink(iv, ivSize));

    FileSource(plainTextFile, true, new StringSink(plain));

    if (strMode == "ECB")
    {
        ECB_Mode<DES>::Encryption e;
        e.SetKey(key, keySize);
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 10000; ++i)
        {
            cipher.clear();
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher), StreamTransformationFilter::PKCS_PADDING));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 10000.0;
        std::cout << "Average time for encryption over 10 000 rounds: " << averageTime << " ms" << std::endl;
    }
    else if (strMode == "CBC")
    {
        CBC_Mode<DES>::Encryption e;
        e.SetKeyWithIV(key, keySize, iv);

        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 10000; ++i)
        {
            cipher.clear();
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher), StreamTransformationFilter::PKCS_PADDING));

        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 10000.0;
        std::cout << "Average time for encryption over 10 000 rounds: " << averageTime << " ms" << std::endl;
    }
    else if (strMode == "OFB")
    {
        OFB_Mode<DES>::Encryption e;
        e.SetKeyWithIV(key, keySize, iv);

        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 10000; ++i)
        {
            cipher.clear();
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher), StreamTransformationFilter::NO_PADDING));

        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 10000.0;
        std::cout << "Average time for encryption over 10 000 rounds: " << averageTime << " ms" << std::endl;
    }
    else if (strMode == "CFB")
    {
        CFB_Mode<DES>::Encryption e;
        e.SetKeyWithIV(key, keySize, iv);

        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 10000; ++i)
        {
            cipher.clear();
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher), StreamTransformationFilter::NO_PADDING));

        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 10000.0;
        std::cout << "Average time for encryption over 10 000 rounds: " << averageTime << " ms" << std::endl;
    }
    else if (strMode == "CTR")
    {
        CTR_Mode<DES>::Encryption e;
        e.SetKeyWithIV(key, keySize, iv);

        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 10000; ++i)
        {
            cipher.clear();
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher), StreamTransformationFilter::NO_PADDING));

        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 10000.0;
        std::cout << "Average time for encryption over 10 000 rounds: " << averageTime << " ms" << std::endl;
    }
    else
    {
        cout << "Error!";
        exit(1);
    }

    encoded.clear();
    if (strCFormat == "Binary")
    {
        encoded = cipher;
        StringSource(encoded, true, new FileSink(cipherTextFile));
    }
    else if (strCFormat == "Hex")
    {
        encoded = hexencode(cipher);
        StringSource(encoded, true, new FileSink(cipherTextFile));
    }
    else if (strCFormat == "Base64")
    {
        encoded = base64encode(cipher);
        StringSource(encoded, true, new FileSink(cipherTextFile));
    }
    else
    {
        cout << "Invalid format for cipher text.";
        exit(1);
    }
    // cout << encoded << endl;
}

void DESDecrypt(const char *mode, const char *keyIVFormat, const char *keyFile, const char *ivFile,
                const char *cipherFormat,
                const char *cipherTextFile, const char *recoverTextFile)
{
    string dataKey, dataIV, decodedKey, decodedIV, cipher, encoded, recovered, decoded;
    string strMode(mode);
    string strFormat(keyIVFormat);
    string strCFormat(cipherFormat);

    // Load key and IV from file
    FileSource(keyFile, true, new StringSink(dataKey));
    if (strMode != "ECB")
        FileSource(ivFile, true, new StringSink(dataIV));
    if (strFormat == "Binary")
    {
        decodedKey = dataKey;
        if (strMode != "ECB")
            decodedIV = dataIV;
    }
    else if (strFormat == "Hex")
    {
        decodedKey = hexdecode(dataKey);
        if (strMode != "ECB")
            decodedIV = hexdecode(dataIV);
    }
    else if (strFormat == "Base64")
    {
        decodedKey = base64decode(dataKey);
        if (strMode != "ECB")
            decodedIV = base64decode(dataIV);
    }
    else
    {
        exit(1);
    }

    int ivSize = 16;
    CryptoPP::byte *iv = new CryptoPP::byte[ivSize];

    CryptoPP::byte *key = new CryptoPP::byte[decodedKey.length()];
    int keySize = decodedKey.length();
    // int ivSize = decodedIV.length();
    StringSource(decodedKey, true, new ArraySink(key, keySize));
    StringSource(decodedIV, true, new ArraySink(iv, ivSize));

    // Load cipher Text from file
    FileSource(cipherTextFile, true, new StringSink(cipher));

    decoded.clear();
    if (strCFormat == "Binary")
    {
        decoded = cipher;
    }
    else if (strCFormat == "Hex")
    {
        decoded = hexdecode(cipher);
    }
    else if (strCFormat == "Base64")
    {
        decoded = base64decode(cipher);
    }
    else
    {
        cout << "Invalid format for cipher text.";
        exit(1);
    }

    if (strMode == "ECB")
    {
        ECB_Mode<DES>::Decryption d;
        d.SetKey(key, keySize);

        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 10000; ++i)
        {
            recovered.clear();
            StringSource s(decoded, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 10000.0;
        std::cout << "Average time for decryption over 10 000 rounds: " << averageTime << " ms" << std::endl;
    }
    else if (strMode == "CBC")
    {
        CBC_Mode<DES>::Decryption d;
        d.SetKeyWithIV(key, keySize, iv);
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 10000; ++i)
        {
            recovered.clear();
            StringSource s(decoded, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 10000.0;
        std::cout << "Average time for decryption over 10 000 rounds: " << averageTime << " ms" << std::endl;
    }
    else if (strMode == "OFB")
    {
        OFB_Mode<DES>::Decryption d;
        d.SetKeyWithIV(key, keySize, iv);
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 10000; ++i)
        {
            recovered.clear();
            StringSource s(decoded, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 10000.0;
        std::cout << "Average time for decryption over 10 000 rounds: " << averageTime << " ms" << std::endl;
    }
    else if (strMode == "CFB")
    {
        CFB_Mode<DES>::Decryption d;
        d.SetKeyWithIV(key, keySize, iv);
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 10000; ++i)
        {
            recovered.clear();
            StringSource s(decoded, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 10000.0;
        std::cout << "Average time for decryption over 10 000 rounds: " << averageTime << " ms" << std::endl;
    }
    else if (strMode == "CTR")
    {
        CTR_Mode<DES>::Decryption d;
        d.SetKeyWithIV(key, keySize, iv);
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 10000; ++i)
        {
            recovered.clear();
            StringSource s(decoded, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 10000.0;
        std::cout << "Average time for decryption over 10 000 rounds: " << averageTime << " ms" << std::endl;
    }
    else
    {
        cout << "Error!";
        exit(0);
    }
    // cout << "recover:" << recovered << endl;
    StringSource(recovered, true, new FileSink(recoverTextFile));
}

int main(int argc, char *argv[])
{
#ifdef __linux__
    std::locale::global(std::locale("C.UTF-8"));
#endif

#ifdef _WIN32
    // Set console code page to UTF-8 on Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    if (argc < 2)
    {
        cout << "Usage: " << endl
             << "genKeyIV <mode> <keySize> <format> <keyFile> <ivFile>" << endl
             << "encrypt <mode> <keyFile> <keyFormat> <cipherTextFormat> <plaintextFile> <cipherTextFile> " << endl
             << "decrypt <mode> <keyFile> <keyFormat> <cipherTextFormat> <cipherTextFile> <recoverTextFile>" << endl;
    }
    string action(argv[1]);
    if (action == "genKeyIV")
    {
        int keySize = std::stoi(argv[3]);
        GenerateKeyAndIV(argv[2], keySize, argv[4], argv[5], argv[6]);
    }
    else if (action == "encrypt")
    {
        DESEncrypt(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8]);
    }
    else if (action == "decrypt")
    {
        DESDecrypt(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8]);
    }
    else
    {
        cout << "Invalid argument: " << action;
        return 1;
    }

    return 0;
}

string base64encode(CryptoPP::byte decoded[], unsigned int size)
{
    string encoded;
    encoded.clear();
    StringSource(decoded, size, true, new Base64Encoder(new StringSink(encoded), false));
    return encoded;
}
string base64decode(CryptoPP::byte encoded[], unsigned int size)
{
    string decoded;
    decoded.clear();
    StringSource(encoded, size, true, new Base64Decoder(new StringSink(decoded)));
    return decoded;
}
string hexencode(CryptoPP::byte decoded[], unsigned int size)
{
    string encoded;
    encoded.clear();
    StringSource(decoded, size, true, new HexEncoder(new StringSink(encoded), false));
    return encoded;
}
string hexdecode(CryptoPP::byte encoded[], unsigned int size)
{
    string decoded;
    decoded.clear();
    StringSource(encoded, size, true, new HexDecoder(new StringSink(decoded)));
    return decoded;
}
string base64encode(string decoded)
{
    string encoded;
    encoded.clear();
    StringSource(decoded, true, new Base64Encoder(new StringSink(encoded), false));
    return encoded;
}
string base64decode(string encoded)
{
    string decoded;
    decoded.clear();
    StringSource(encoded, true, new Base64Decoder(new StringSink(decoded)));
    return decoded;
}
string hexencode(string decoded)
{
    string encoded;
    encoded.clear();
    StringSource(decoded, true, new HexEncoder(new StringSink(encoded), false));
    return encoded;
}
string hexdecode(string encoded)
{
    string decoded;
    decoded.clear();
    StringSource(encoded, true, new HexDecoder(new StringSink(decoded)));
    return decoded;
}
