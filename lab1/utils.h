#pragma once
#ifndef UTILS_H
#define UTILS_H
#include <string>
#include <vector>
#include <cstdint>
std::vector<uint8_t> str2vector(std::string str);
std::string vector2str(std::vector<uint8_t> byteVector);
std::vector<uint8_t> hex2byte(std::string hexStr);
std::string byte2hex(std::vector<uint8_t> byteVector);
#endif