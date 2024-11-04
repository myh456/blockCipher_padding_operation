#include "operation.hpp"

#include <iostream>

void Operation::InitSM4(bitset<128> key) {
    this->sm4 = new SM4(key);
}

void Operation::setOperationMode(int mode) {
    this->OperationMode = mode;
}

Operation::Operation() { }

Operation::Operation(bitset<128> key, int mode) :OperationMode(mode), sm4(new SM4(key)) { }

vector<bitset<128>> Operation::encECB(vector<bitset<128>> Ms) {
    vector<bitset<128>> Cs = vector<bitset<128>>(Ms.size(), 0x00);
    for (bitset<128> m : Ms) {
        // 加密过程可并行
        Ms.push_back(sm4->enc(m));
    }
    return Cs;
}

vector<bitset<128>> Operation::decECB(vector<bitset<128>> Cs) {
    vector<bitset<128>> Ms;
    for (bitset<128> c : Cs) {
        // 解密过程可并行
        Ms.push_back(sm4->dec(c));
    }
    return Ms;
}

vector<bitset<128>> Operation::encCBC(vector<bitset<128>> Ms, bitset<128> IV) {
    vector<bitset<128>> Cs;
    Cs.push_back(sm4->enc(IV ^ Ms[0]));
    for (int i = 1; i < Ms.size(); i++) {
        // 加密时需要上一个密文块，不可并行
        Cs.push_back(sm4->enc(Cs[i - 1] ^ Ms[i]));
    }
    // IV为0时，得到的最后一个密文块被称为CBCMAC
    return Cs;
}

vector<bitset<128>> Operation::decCBC(vector<bitset<128>> Cs, bitset<128> IV) {
    vector<bitset<128>> Ms;
    Ms.push_back(sm4->dec(Cs[0]) ^ IV);
    for (int i = 1; i < Cs.size(); i++) {
        // 解密时需要的上一个密文块已知，可并行
        Ms.push_back(sm4->dec(Cs[i]) ^ Cs[i - 1]);
    }
    return Ms;
}

vector<bitset<128>> Operation::encCFB(vector<bitset<128>> Ms, bitset<128> IV) {
    vector<bitset<128>> Cs;
    Cs.push_back(sm4->enc(IV) ^ Ms[0]);
    for (int i = 1; i < Ms.size(); i++) {
        // 加密时需要上一个密文块，不可并行 
        Cs.push_back(sm4->enc(Cs[i - 1]) ^ Ms[i]);
    }
    return Cs;
}

vector<bitset<128>> Operation::decCFB(vector<bitset<128>> Cs, bitset<128> IV) {
    // 加解密过程相同
    return this->encCFB(Cs, IV);
}

vector<bitset<128>> Operation::encOFB(vector<bitset<128>> Ms, bitset<128> IV) {
    vector<bitset<128>> Cs;
    for (int i = 0; i < Ms.size(); i++) {
        // 加密时每块加密使用的IV都需要上一轮的IV结果，不可并行，这个过程可以提前准备
        IV = sm4->enc(IV);
        Cs.push_back(IV ^ Ms[i]);
    }
    return Cs;
}

vector<bitset<128>> Operation::decOFB(vector<bitset<128>> Cs, bitset<128> IV) {
    // 加解密过程相同
    return this->decCFB(Cs, IV);
}

vector<bitset<128>> Operation::encCTR(vector<bitset<128>> Ms, bitset<128> IV) {
    vector<bitset<128>> Cs;
    // CTR使用的计数器前64位为nonce(number once)，这里直接用IV后64位了，后64位为分组序号
    IV <<= 64;
    for (int i = 0; i < Ms.size(); i++) {
        // 加密时nonce和分组序号提前可知，可并行
        Cs.push_back(sm4->enc(IV | bitset<128>(i)) ^ Ms[i]);
    }
    return Cs;
}

vector<bitset<128>> Operation::decCTR(vector<bitset<128>> Cs, bitset<128> IV) {
    // 加解密过程相同
    return this->encCTR(Cs, IV);
}

vector<bitset<128>> Operation::enc(vector<bitset<128>> Ms, bitset<128> IV) {
    if (sm4 == nullptr) {
        cerr << "先确定好密钥";
        return vector<bitset<128>>(0, 0);
    }

    switch (this->OperationMode) {
    case OperationMode::ECB:
        return encECB(Ms);

    case OperationMode::CBC:
        return encCBC(Ms, IV);

    case OperationMode::CFB:
        return encCFB(Ms, IV);

    case OperationMode::OFB:
        return encOFB(Ms, IV);

    case OperationMode::CTR:
        return encCTR(Ms, IV);

    default:
        cerr << "先选择一个模式";
        return vector<bitset<128>>(0, 0);
    }
}

vector<bitset<128>> Operation::dec(vector<bitset<128>> Cs, bitset<128> IV) {
    if (sm4 == nullptr) {
        cerr << "先确定好密钥";
        return vector<bitset<128>>(0, 0);
    }

    switch (this->OperationMode) {
    case OperationMode::ECB:
        return decECB(Cs);

    case OperationMode::CBC:
        return decCBC(Cs, IV);

    case OperationMode::CFB:
        return decCFB(Cs, IV);

    case OperationMode::OFB:
        return decOFB(Cs, IV);

    case OperationMode::CTR:
        return decCTR(Cs, IV);

    default:
        cerr << "先选择一个模式";
        return vector<bitset<128>>(0, 0);
    }
}
