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

	ssl_certificate      /usr/local/nginx/conf/tlcp_server_certs.pem;
	ssl_certificate_key  /usr/local/nginx/conf/tlcp_server_keys.pem;
	ssl_password_file    /usr/local/nginx/conf/tlcp_server_password.txt;
	ssl_ecdh_curve       sm2p256v1;

	location / {
		root   html;
		index  index.html index.htm;
	}
}
```

其中`server_tlcp_certs.pem`是一个完整的服务器证书链，`server_tlcp_keys.pem`相对特殊，这里有两个PEM格式的私钥，分别是签名私钥和加密私钥，这两个私钥需要用相同的加密口令，并且口令存储在`server_password.txt`中。



### 生成服务器TLCP证书

TLCP服务器的完整证书链是由服务器终端签名证书、服务器终端加密证书、中间CA证书以及根CA证书构成，在一个标准的证书链PEM文件中，其中的PEM数据是依次按照终端签名证书、终端加密证书、一个或多个中间CA证书的顺序前后排列的。终端签名证书和终端加密证书应该有完全相同的Subject名字，并且通过KeyUsage等属性进行区别。在TLCP协议中，服务器向客户端提供的证书链中不应包含最后的根CA证书。两个终端证书都是由同一个中间CA证书签名的，中间CA证书按顺序排列，前一个中间CA证书由后一个中间CA证书签名。最后一个中间CA证书应该由根CA证书签名。

下面的例子生成一个TLCP服务器证书链，这个证书链由服务器终端签名证书、服务器终端加密证书、一个中间CA证书和一个不存储在证书链中的根CA证书构成。按证书链相反的顺序生成。

首先，生成根CA证书的私钥，以及自签名的根CA证书。

```bash
$ gmssl sm2keygen -pass P@ssw0rd -out rootcakey.pem
$ gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN ROOTCA -days 3650 -key rootcakey.pem -pass P@ssw0rd -out rootcacert.pem -key_usage keyCertSign -key_usage cRLSign -ca
```

第二步，生成中间CA的私钥和证书请求文件(REQ)，然后用根CA证书私钥对中间CA的REQ进行签名，生成中间CA证书。

```bash
$ gmssl sm2keygen -pass P@ssw0rd -out cakey.pem
$ gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN "Sub CA" -key cakey.pem -pass P@ssw0rd -out careq.pem
$ gmssl reqsign -in careq.pem -days 365 -key_usage keyCertSign -path_len_constraint 0 -cacert rootcacert.pem -key rootcakey.pem -pass P@ssw0rd -out cacert.pem -ca
```

第三步，生成服务器终端签名证书的私钥、证书请求文件(REQ)，用中间CA私钥签发终端签名证书。

```bash
$ gmssl sm2keygen -pass P@ssw0rd -out signkey.pem
$ gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key signkey.pem -pass P@ssw0rd -out signreq.pem
$ gmssl reqsign -in signreq.pem -days 365 -key_usage digitalSignature -cacert cacert.pem -key cakey.pem -pass P@ssw0rd -out signcert.pem
```

第四步，按第三步相同的方式生成终端加密证书，注意证书的Subject和签名证书保持一致，但是使用不同的`-key_usage`选项。注意在当前版本的GmSSL-OCL中，需要保证签名和加密私钥使用相同的口令。

```bash
$ gmssl sm2keygen -pass P@ssw0rd -out enckey.pem
$ gmssl reqgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN localhost -key enckey.pem -pass P@ssw0rd -out encreq
$ gmssl reqsign -in encreq.pem -days 365 -key_usage keyEncipherment -cacert cacert.pem -key cakey.pem -pass P@ssw0rd -out enccert.pem
```

第五步，将终端证书和中间CA证书写入服务器证书链PEM文件，将根CA证书提供给TLCP客户端。通过`gmssl certparse`可以打印证书链，检查生成的证书链内容是否正确。

```bash
$ cat signcert.pem > tlcp_server_certs.pem
$ cat enccert.pem >> tlcp_server_certs.pem
$ cat cacert.pem >> tlcp_server_certs.pem
$ gmssl certparse -in tlcp_server_certs.pem
```

第六步，将终端签名私钥和加密私钥按顺序写入私钥PEM文件。

```bash
$ cat signkey.pem > tlcp_server_keys.pem
$ cat enckey.pem >> tlcp_server_keys.pem
```

此时，服务器需要的TLCP证书链文件和私钥文件就准备好了。

### 安装服务器证书链和私钥文件

在安装完Nginx服务器后，需要将服务器证书链PEM文件、服务器私钥PEM文件和服务器私钥口令分别拷贝到`nginx.conf`配置文件中设置的路径中。其中口令字符串需要写入到`.txt`格式的口令文件中。

```bash
$ cp tlcp_server_certs.pem /usr/local/nginx/conf/tlcp_server_certs.pem
$ cp tlcp_server_keys.pem /usr/local/nginx/conf/tlcp_server_keys.pem
$ echo P@ssw0rd > /usr/local/nginx/conf/tlcp_server_password.txt
```

### 启动服务器并测试HTTPS

注意，在macOS上，编译安装nginx之后需要执行

```bash
sudo install_name_tool -add_rpath /usr/local/lib /usr/local/nginx/sbin/nginx
```

然后可以用gmssl的命令行客户端进行验证，注意，客户端需要用于验证服务器的根CA证书，客户端证书和私钥，这些文件保存在`client`目录下。

```bash
gmssl tlcp_client -host localhost -port 4443 -cacert rootcacert.pem
```

在gmssl命令行连接服务器之后需要发送三行消息

```
GET / HTTP/1.1
Host: localhost
<return>
```

然后可以看到Nginx返回的index.html。此时连接没有中断，可再次访问。

如果gmssl客户端发送的请求格式不正确，例如发送了`GET /`，那么Nginx-1.22仍然返回index.html，但是会shutdown SSL连接。



