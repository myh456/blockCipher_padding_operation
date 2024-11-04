#include "padding.hpp"
#include <iostream>

std::bitset<128> strToBitset(std::string str) {
    std::bitset<128> bs;
    for (int index = 0; index < 16; index++) {
        bs <<= 8;
        bs |= str[index];
    }
    return bs;
}

std::vector<std::bitset<128>> Padding::generateBlock(std::string plain) {
    std::vector<std::bitset<128>> res;
    while (true) {
        if (plain.size() > 16) {
            res.push_back(strToBitset(plain.substr(0, 16)));
            plain.erase(0, 16);
        } else {
            switch (this->paddingMode) {
            case PaddingMode::NoPadding:            // 不填充
                if (plain.size() != 16) {
                    std::cerr << "乖，别闹" << std::endl;
                    exit(0);
                }
                res.push_back(strToBitset(plain));
                break;

            case PaddingMode::ZeroPadding:          // 填充0
                // 正好可以完成分组时不填充
                res.push_back(strToBitset(plain + std::string(16 - plain.size(), 0x00)));
                break;

            case PaddingMode::RandomPadding: {      // 随机填充
                    // 加大括号的原因和作用域有关
                    std::string randStr = "";
                    // 正好可以完成分组时不填充
                    while (randStr.size() + plain.size() != 16) {
                        // 以时间为种子生成随机数
                        srand(time(NULL));
                        randStr += rand() % 0xff;
                    }
                    res.push_back(strToBitset(plain + randStr));
                } break;

            case PaddingMode::ANSI__X_923__Padding: // 0x00填充，最后一字节表示填充的0x00的个数
                if (plain.size() == 16) {
                    res.push_back(strToBitset(plain));
                    // 正好可以完成分组时也需要填充
                    res.push_back(strToBitset(std::string(15, 0x00) + (char)0x0f));
                } else {
                    res.push_back(strToBitset(plain + std::string(15 - plain.size(), 0x00) + (char)(15 - plain.size())));
                }
                break;

            case PaddingMode::ISO__7816_4__Padding: // 填充一个0x80，然后填充0x00
                plain += 0x80;
                if (plain.size() > 16) {
                    // 可能填充完0x80后刚好17个了(正好可以完成分组时也需要填充)
                    res.push_back(strToBitset(plain.substr(0, 16)));
                    plain.erase(0, 16);
                }
                res.push_back(strToBitset(plain + std::string(16 - plain.size(), 0x00)));
                break;
            case PaddingMode::PKCS5_Padding:
                std::cout << "SM4算法明文分组需要16字节, 帮你选PKCS7 Padding了";

            case PaddingMode::PKCS7_Padding:        // 以需要填充的长度来填充
                if (plain.size() == 16) {
                    res.push_back(strToBitset(plain));
                    // 正好可以完成分组时也需要填充
                    res.push_back(strToBitset(std::string(16, 0x10)));
                } else {
                    res.push_back(strToBitset(plain + std::string(16 - plain.size(), 16 - plain.size())));
                }
                break;

            default:
                std::cerr << "先选个模式再用吧" << std::endl;
                exit(0);
            }
            break;
        }
    }
    return res;
}

std::string Padding::restoreBlock(std::vector<std::bitset<128>> block) {
    std::string str = "";
    for (int i = 0; i < block.size() - 1; i++) {
        for (int j = 0; j < 16; j++) {
            str += (char)(block[i] >> (120 - j * 8) & std::bitset<128>(0xff)).to_ulong();
        }
    }
    switch (this->paddingMode) {
    case PaddingMode::NoPadding:
        // 没填充直接还原就行

    case PaddingMode::ZeroPadding:
        // 无法还原，明文末尾可能会有无意义的0

    case PaddingMode::RandomPadding:
        // 无法还原，明文末尾可能会有乱码
        for (int j = 0; j < 16; j++) {
            str += (char)(*(block.end() - 1) >> (120 - j * 8) & std::bitset<128>(0xff)).to_ulong();
        }
        break;

    case PaddingMode::ANSI__X_923__Padding: {
            // 不还原填充的字节就行
            int len = 15 - (*(block.end() - 1) & std::bitset<128>(0xff)).to_ulong();
            for (int j = 0; j < len; j++) {
                str += (char)(*(block.end() - 1) >> (120 - j * 8) & std::bitset<128>(0xff)).to_ulong();
            }
        } break;

    case PaddingMode::ISO__7816_4__Padding: {
            int len = 0;
            // 要先查出填充的个数
            for (int j = 0; j < 16; j++) {
                // 最后的不是0的元素
                if (!(*(block.end() - 1) >> (j * 8) & std::bitset<128>(0xff)).to_ulong()) {
                    len = 15 - j;
                }
            }
            for (int j = 0; j < len; j++) {
                str += (char)(*(block.end() - 1) >> (120 - j * 8) & std::bitset<128>(0xff)).to_ulong();
            }
        } break;

    case PaddingMode::PKCS5_Padding:
        // SM4用不了这种模式

    case PaddingMode::PKCS7_Padding: {
            // 不还原填充的字节就行
            int len = 16 - (*(block.end() - 1) & std::bitset<128>(0xff)).to_ulong();
            for (int j = 0; j < len; j++) {
                str += (char)(*(block.end() - 1) >> (120 - j * 8) & std::bitset<128>(0xff)).to_ulong();
            }
        } break;

    default:
        std::cerr << "???";
        exit(0);
    }
    return str;
}

void Padding::setPaddingMode(int mode) {
    this->paddingMode = mode;
}

Padding::Padding() { }
Padding::Padding(int mode) : paddingMode(mode) { }