# OpenSSL-Compatibility-Layer
OpenSSL-Compatible-Layer 是 GmSSL 项目下的一个子项目，提供一个将 GmSSL 接口封装为 OpenSSL 兼容接口的层。该项目旨在为需要使用 GmSSL 加密功能但构建于 OpenSSL 之上的应用程序提供无缝集成，可以将基于OpenSSL的程序，在无需修改代码的情况下迁移至GmSSL，并自动调用GmSSL中的国密算法。

## 编译和安装

OpenSSL-Compatible-Layer需要预先安装CMake和GCC编译工具链。下载 OpenSSL-Compatible-Layer 源代码并解压，进入源代码目录，执行

```bash
mkdir build
cd build
cmake ..
make
sudo make install
```

在安装完成后，会在`/usr/local/include`目录下创建`openssl`目录并安装OpenSSL同名的头文件，并且在`/usr/local/lib`目录下安装`libcrypto`和`libssl`两个和OpenSSL同名的库文件。

## 兼容性

由于OpenSSL-Compatible-Layer并没有封装所有的OpenSSL接口，因此无法兼容所有依赖OpenSSL的应用，下面是OpenSSL-Compatible-Layer兼容的项目列表：

* to be added
