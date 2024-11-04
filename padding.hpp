#pragma once

#include <vector>
#include <bitset>
#include <string>

enum PaddingMode {
    NoPadding,              // 正好可以完成分组时使用
    ZeroPadding,            // 0x00填充
    RandomPadding,          // 随机填充
    ANSI__X_923__Padding,   // 0x00填充，最后一字节表示填充的0x00的个数
    ISO__7816_4__Padding,   // 填充一个0x80，然后填充0x00
    PKCS5_Padding,          // 分组加密算法要求分组为8字节时，以需要填充的长度来填充
    PKCS7_Padding           // 以需要填充的长度来填充(PKCS5是PKCS7的特例)
};

class Padding {
private:
    // 选中的填充模式(-1相当于未选中)
    int paddingMode = -1;
public:
    std::vector<std::bitset<128>> generateBlock(std::string plain);
    std::string restoreBlock(std::vector<std::bitset<128>> block);
    void setPaddingMode(int mode);
    Padding();
    Padding(int mode);
};
