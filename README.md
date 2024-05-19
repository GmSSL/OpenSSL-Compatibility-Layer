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

由于OpenSSL-Compatible-Layer并没有封装所有的OpenSSL接口，因此无法兼容所有依赖OpenSSL的应用。

### Nginx

首先应该确保GmSSL和OpenSSL-Compatible-Layer已经安装，并且保证默认的系统路径中的头文件和库文件的确来自OpenSSL-Compatible-Layer。如果默认系统路径是`/usr/local`，那么检查`/usr/local/include/openssl/opensslv.h`是否为OCL的版本，以及检查`/usr/local/lib/libcrypto.so`是否依赖`libgmssl`。

进入Nginx源码目录，执行

```bash
./configure --with-http_ssl_module --with-debug --without-http_rewrite_module
```

注意，必须通过`--with-http_ssl_module`显式指定编译SSL模块。`--with-debug`是可选的，可以方便出现问题后查看打印的错误信息。如果系统默认没有安装PCRE，可以设置`--without-http_rewrite_module`避免配置错误。

配置完成后，编译并安装

```bash
make
sudo make install
```

Nginx的二进制程序、配置文件、日志文件等默认均安装在`/usr/loca/nginx`目录下，可以执行`sudo /usr/local/nginx/bin/nginx`来启动Nginx。在默认情况下Nginx并没有启用SSL功能，需要修改配置文件，并提供SSL需要的证书、密钥文件。

修改Nginx的配置文件`/usr/local/nginx/conf/nginx.conf`，启用SSL

```
server {
	listen       4443 ssl;
	server_name  localhost;

	ssl_certificate      /usr/local/nginx/conf/server_tlcp_certs.pem;
	ssl_certificate_key  /usr/local/nginx/conf/server_tlcp_keys.pem;
	ssl_password_file    /usr/local/nginx/conf/server_password.txt;
	ssl_ecdh_curve       sm2p256v1;

	ssl_client_certificate /usr/local/nginx/conf/client_verify_cacert.pem;
	ssl_verify_client on;
	ssl_verify_depth 1;

	location / {
		root   html;
		index  index.html index.htm;
	}
}
```

其中`server_tlcp_certs.pem`是一个完整的服务器证书链，`server_tlcp_keys.pem`相对特殊，这里有两个PEM格式的私钥，分别是签名私钥和加密私钥，这两个私钥需要用相同的加密口令，并且口令存储在`server_password.txt`中。

