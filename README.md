# 分组加密算法所使用的填充算法和工作模式
加密算法使用了SM4,代码和[SM4-encryption](https://github.com/myh456/SM4-encryption)一样
## 使用方法
``` shell
git clone https://github.com/myh456/blockCipher_padding_operation.git
cd ./blockCipher_padding_operation
g++ ./*.cpp -o main.out    # Windows下写main.exe，对应下一行同样
./main.out
```
在[main.cpp](./main.cpp)中可以修改需要使用的填充算法和工作模式