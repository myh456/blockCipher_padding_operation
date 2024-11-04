#pragma once

#include "sm4.hpp"

enum OperationMode {
    ECB,    // 电子密码本，明文分割成固定大小的块，逐块加密
    CBC,    // 密码分组链接，明文块和前一个密文块异或后再加密
    CFB,    // 密码反馈，前一个密文块加密后和当前明文块异或
    OFB,    // 输出反馈，IV多次加密后，每次加密的结果依次和明文块异或后再加密
    CTR     // 计数器，将逐次累加的计数器进行加密来生成密钥流，相当于把分组加密转换成了流加密
};

class Operation {
private:
    // 选中的工作模式(-1相当于未选中)
    int OperationMode = -1;
    // SM4对象
    SM4* sm4 = nullptr;

    // ECB模式加解密
    vector<bitset<128>> encECB(vector<bitset<128>> Ms);
    vector<bitset<128>> decECB(vector<bitset<128>> Cs);

    // CBC模式加解密
    vector<bitset<128>> encCBC(vector<bitset<128>> Ms, bitset<128> IV);
    vector<bitset<128>> decCBC(vector<bitset<128>> Cs, bitset<128> IV);

    // CFB模式加解密
    vector<bitset<128>> encCFB(vector<bitset<128>> Ms, bitset<128> IV);
    vector<bitset<128>> decCFB(vector<bitset<128>> Cs, bitset<128> IV);

    // OFB模式加解密
    vector<bitset<128>> encOFB(vector<bitset<128>> Ms, bitset<128> IV);
    vector<bitset<128>> decOFB(vector<bitset<128>> Cs, bitset<128> IV);

    // CTR模式加解密
    vector<bitset<128>> encCTR(vector<bitset<128>> Ms, bitset<128> IV);
    vector<bitset<128>> decCTR(vector<bitset<128>> Cs, bitset<128> IV);
public:
    // 加密(ECB模式不用赋值IV)
    vector<bitset<128>> enc(vector<bitset<128>> Ms, bitset<128> IV = 0x00);
    // 解密(ECB模式不用赋值IV)
    vector<bitset<128>> dec(vector<bitset<128>> Ms, bitset<128> IV = 0x00);

    void InitSM4(bitset<128> key);
    void setOperationMode(int mode);
    Operation();
    Operation(bitset<128> key, int mode);
};