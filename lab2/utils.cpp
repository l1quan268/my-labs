#include "utils.h"
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <codecvt>
std::vector<uint8_t> str2vector(std::string str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::string vector2str(std::vector<uint8_t> byteVector) {
    return std::string(byteVector.begin(), byteVector.end());
}

std::vector<uint8_t> hex2byte(std::string hexStr) {
    std::vector<uint8_t> byteVector;
    for (size_t i = 0; i < hexStr.size(); i += 2) {
        std::string byteStr = hexStr.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        byteVector.push_back(byte);
    }
    return byteVector;
}

std::string byte2hex(std::vector<uint8_t> byteVector) {
    std::stringstream ss;
    for (uint8_t b : byteVector) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return ss.str();
}
