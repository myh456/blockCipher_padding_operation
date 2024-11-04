#include "padding.hpp"
#include "operation.hpp"

#include <iostream>
using namespace std;

int main(int argc, char const* argv[]) {
    Padding pd = Padding(PaddingMode::ANSI__X_923__Padding);
    Operation op;
    string M, K, IV;
    bitset<128> key, iv;
    vector<bitset<128>> cipher;
    cout << "输入明文:" << endl;
    cin >> M;
    cout << "输入密钥(16个字符):" << endl;
    cin >> K;
    cout << "输入IV(16个字符):" << endl;
    cin >> IV;
    for (int i = 0; i < 16; i++) {
        key <<= 8;
        key |= K[i];
        iv <<= 8;
        iv |= IV[i];
    }
    op = Operation(key, OperationMode::CBC);
    cout << "密文:" << endl;
    cipher = op.enc(pd.generateBlock(M), iv);
    cout << pd.restoreBlock(cipher) << endl;;
    cout << "明文:" << endl;
    cout << pd.restoreBlock(op.dec(cipher, iv)) << endl;
    return 0;
}
