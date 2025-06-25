#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <string>
#include <cstdlib>
#include <cstdint>
#include <locale>
#include <codecvt>
#ifdef _WIN32
#include <windows.h>
#endif

#include "CBC_mode.h"
#include "AES.h"
#include "utils.h"

using namespace std;

void AESEncrypt(const char *keyFile, const char *ivFile, const char *plainTextFile, const char *cipherTextFile)
{
    string KEY, IV, line, plain;
    string strKeyFile(keyFile);
    string strIVFile(ivFile);
    string strPlainTextFile(plainTextFile);
    string strCipherTextFile(cipherTextFile);

    ifstream fileKey(strKeyFile);
    if (!fileKey.is_open()) { cerr << "Can't open file " << strKeyFile << endl; exit(1); }
    getline(fileKey, KEY); fileKey.close();

    ifstream fileIV(strIVFile);
    if (!fileIV.is_open()) { cerr << "Can't open file " << strIVFile << endl; exit(1); }
    getline(fileIV, IV); fileIV.close();

    ifstream filePlain(strPlainTextFile);
    if (!filePlain.is_open()) { cerr << "Can't open file " << strPlainTextFile << endl; exit(1); }
    while (getline(filePlain, line)) plain += line + "\n";
    filePlain.close();

    vector<uint8_t> byte_pl = str2vector(plain);
    vector<uint8_t> byte_key = str2vector(KEY);
    vector<uint8_t> byte_iv = str2vector(IV);

    // THÊM DEBUG
    cout << "Key length: " << byte_key.size() << " bytes" << endl;
    cout << "IV length: " << byte_iv.size() << " bytes" << endl;
    cout << "Plaintext length: " << byte_pl.size() << " bytes" << endl;

    CBC_mode mode(byte_key, byte_iv);
    vector<uint8_t> enc_data;

    auto start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 10000; ++i) {
        enc_data = mode.cbc_encrypt(byte_pl);
    }
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    double avg = static_cast<double>(duration) / 10000.0;
    
    // THÊM DEBUG
    cout << "Encrypted data length: " << enc_data.size() << " bytes" << endl;
    cout << "Average time for encryption over 10000 rounds: " << avg << " ms" << endl;

    if (enc_data.empty()) {
        cerr << "Encryption failed - no data produced" << endl;
        exit(1);
    }

    string hexString = byte2hex(enc_data);
    ofstream fileCipher(strCipherTextFile);
    if (!fileCipher.is_open()) { cerr << "Can't open file " << strCipherTextFile << endl; exit(1); }
    fileCipher << hexString;
    fileCipher.close();
    
    cout << "Encryption completed successfully" << endl;
}

void AESDecrypt(const char *keyFile, const char *ivFile, const char *cipherTextFile, const char *recoverTextFile)
{
    string KEY, IV, line, cipher;
    string strKeyFile(keyFile);
    string strIVFile(ivFile);
    string strCipherTextFile(cipherTextFile);
    string strRecoverFile(recoverTextFile);

    ifstream fileKey(strKeyFile);
    if (!fileKey.is_open()) { cerr << "Can't open file " << strKeyFile << endl; exit(1); }
    getline(fileKey, KEY); fileKey.close();

    ifstream fileIV(strIVFile);
    if (!fileIV.is_open()) { cerr << "Can't open file " << strIVFile << endl; exit(1); }
    getline(fileIV, IV); fileIV.close();

    ifstream fileCipher(strCipherTextFile);
    if (!fileCipher.is_open()) { cerr << "Can't open file " << strCipherTextFile << endl; exit(1); }
    getline(fileCipher, cipher); fileCipher.close();

    vector<uint8_t> byte_key = str2vector(KEY);
    vector<uint8_t> byte_iv = str2vector(IV);
    vector<uint8_t> cipher_bytes = hex2byte(cipher);

    if (cipher_bytes.size() < 32 || cipher_bytes.size() % 16 != 0) {
        cerr << "Invalid ciphertext length for CBC (not multiple of 16)." << endl;
        exit(1);
    }

    CBC_mode mode(byte_key, byte_iv);
    vector<uint8_t> dec_data;

    auto start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 10000; ++i) {
        dec_data = mode.cbc_decrypt(cipher_bytes);
    }
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    double avg = static_cast<double>(duration) / 10000.0;
    cout << "Average time for decryption over 10000 rounds: " << avg << " ms" << endl;

    string recovered = vector2str(dec_data);
    ofstream fileRec(strRecoverFile);
    if (!fileRec.is_open()) { cerr << "Can't open file " << strRecoverFile << endl; exit(1); }
    fileRec << recovered;
    fileRec.close();
}

int main(int argc, char *argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    if (argc < 2) {
        cout << "Usage:\n"
             << "encrypt <keyFile> <ivFile> <plainTextFile> <cipherTextFile>\n"
             << "decrypt <keyFile> <ivFile> <cipherTextFile> <recoverTextFile>\n";
        return 1;
    }

    string mode(argv[1]);
    if (mode == "encrypt") {
        AESEncrypt(argv[2], argv[3], argv[4], argv[5]);
    } else if (mode == "decrypt") {
        AESDecrypt(argv[2], argv[3], argv[4], argv[5]);
    } else {
        cout << "Invalid argument: " << mode << endl;
        return 1;
    }
    return 0;
}
