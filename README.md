

# APP网络传输安全

[TOC]

## 一、`APP`通信安全威胁

### 1.1 背景

* 数据明文传输造成用户数据、隐私泄露；
* 数据未校验导致的数据篡改、重放攻击；
* 证书校验漏洞导致的中间人攻击漏洞。

### 1.2 加密算法

#### 1.2.1 对称加密

* 采用单秘钥加密，加解密秘钥同一份；
* 代表算法：`DES`、`3DES`、`AES`、`RC2`、`RC4`；
* 优点：加解密效率高，算法简单，合适加密大量数据；
* 缺点：秘钥维护较复杂，泄漏后就没有安全性可言。

#### 1.2.2 非对称加密

* 非对称公私钥对，一个密钥用于加密，另个一个解密；
* 代表算法：`RSA`、`ECC`；
* 优点：安全性高，由公钥无法推导出私钥，适应网络传输场景；
* 缺点：加密效率偏低。

### 1.3 `HTTP/HTTPS`

#### 1.3.1 `HTTP`

`HyperText Transfer Protocol`（超文本传输协议）被用于在`Web`浏览器和网站服务器之间传递消息，在`TCP/IP`中处于应用层。

* 通讯使用明文，内容可能被窃听；
* 不验证通信方的身份，因此有可能遭遇伪装；
* 无法证明报文的完整性，所以有可能遭到篡改。

#### 1.2.2 `HTTPS`

`HTTPS`中的`S`表示`SSL`或者`TLS`，就是在原`HTTP`的基础上加上一层用于数据加密、解密、身份认证的安全层。

* `HTTP`+加密+认证+完整性保护=`HTTPS`

### 1.4 `APP`网络应用场景

* 使用`http`，不做任何加密，相当于裸奔，初级工程师都可以轻易窥探全部业务数据；
* 使用`http`，但所有的流量都通过预埋在客户端的`key`进行`AES`加密，流量基本安全，不过一旦客户端代码被反编译窃取`key`，又会回到裸奔状态；
* 使用`http`，但`AES`使用的`key`通过客户端以`GUID`的方式临时生成，为了保证`key`能安全地送达服务器，势必要使用服务器的公钥进行加密，所有要预埋服务器证书，又涉及到证书过期更新机制，而且无法动态协商使用的对称加密算法，安全性还是有瑕疵。

## 二、数据传输加密和证书校验

### 2.1 加密传输安全建议

* 尽量使用`HTTPS`；
* 不要用明文传输密码；
* 请求带上数据签名防篡改；
* `HTTP`请求使用临时秘钥；
* `AES`使用`CBC`模式；
* `Post`并不比`Get`安全，都要加密和签名处理。

### 2.2 `HTTPS`证书校验

* `CA`：`Certificate Authority`, `CA`用自己的私钥签发数字证书，数字证书中包含`A`的公钥，然后`B`可以用`CA`的根证书中的公钥来解密`CA`签发的证书，从而拿到合法的公钥。
* 中间`CA`：大多数`CA`不直接签署服务器证书，而是签署中间`CA`，然后用中间`CA`来签署服务器证书。这样根证书就可以离线存储来确保安全，即使中间证书出了问题，可以用根证书重新签署中间证书。
* 证书校验：`HTTPS`握手开始后，服务器会把整个证书链发送给客户端，给客户端做校验。校验的过程是要找到这样一条证书链，链中每个相邻节点，上级的公钥可以校验通过下级的证书，链的根节点是设备信任的锚点。

### 2.3 `HTTPS`配置

#### 2.3.1 服务端

* 服务端生成公私钥对；
* 给`Tomcat`服务器配置`Https`；
* 导出证书。

#### 2.3.2 客户端

* 将证书集成到`APK`文件中；
* 发送网络请求，获取证书，读取`https`网站的数据。

### 2.3 `https API`

* `HttpsURLConnection`

```java
URL url = new URL("https://google.com");
HttpsURLConnection urlConnection = url.openConnection();
InputStream in = urlConnection.getInputStream();
```

* `SSLSocketFactory`

```java
private synchronized SSLSocketFactory getDefaultSSLSocketFactory() {
  try {
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, null, null);
    return defaultSslSocketFactory = sslContext.getSocketFactory();
  } catch(GeneralSecurityException e) {
    throw new AssertionError();
  }
}
```

* `TrustManager`

```java
public interface X509TrustManager extends TrustManager {
  public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException;
  
  public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException;
  
  public X509Certificate[] getAcceptedIssuers();
}
```

### 2.4 `Https`验证证书问题

#### 2.4.1 `SSLHandshakeException`

> 2. 颁发服务器证书的`CA`未知；
> 3. 服务器证书不是`CA`签名的，而是自签名的；
> 4. 服务器配置缺少中间`CA`.

**解决方案：** 自定义`SSL`配置信任`CA`.

```java
//取到证书的输入流
InputStream stream = getAssets().open("server.crt");
KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
keystore.load(null);
Certificate certificate = CertificateFactory.getInstance("X509").generateCertificate(stream);
//创建Keystore包含我们的证书
keystore.setCertificateEntry("ca", certificate);

//创建TrustManager, 仅信任keyStore中的证书
String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
tmf.init(keyStore);

//用TrustManager初始化一个SSLContext
SSLContext context = SSLContext.getInstance("TLS");
context.init(null, tmf.getTrustManagers(), null);

URL url = new URL(path);
HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
conn.setSSLSocketFactory(context.getSocketFactory());
InputStream in = urlConnection.getInputStream();
```

## 三、常见的安全提升方案

### 3.1 安全隐患

#### 3.1.1 中间人攻击

在迷茫学和计算机安全领域中，中间人攻击（`Man-in-the-middle attack`，通常缩写为`MITM`）是指攻击者与通讯的两端分别创建独立的联系，并交换其所收到的数据，使通讯的两端认为他们正在通过一个私密的连接与对方直接对话，但事实上整个会话都被攻击者完全控制。在中间人攻击中，攻击者可以拦截通讯双方的通话并插入新的内容。

原因：

* `https`中`SSL`配置漏洞；
* 证书颁发机构（`Certification Authority`）被攻击导致私钥泄密等。

#### 3.1.2 `https`中间人攻击漏洞

漏洞原理：

* 自定义的`X509TrustManager`不校验证书；
* 或实现的自定义`HostnameVerifier`不校验域名接受任意域名；
* 或使用`setHostnameVerifier(ALLOW_ALL_HOSTNAME_VERIFIER)`；
* 或重写`WebViewClient`的`onReceivedSslError`方法时，调用`proceed`忽略证书验证错误信息。

安全建议：

* 在自定义实现`X509TrustManager`时，在`checkServerTrusted`中对服务器信息进行严格校验；
* 在自定义实现`HostnameVerifier`时，在`verify`中对`Hostname`进行严格校验；
* `setHostnameVerifier`方法中使用`STRICT_HOSTNAME_VERIFIER`进行严格证书校验；
* 在重写`WebViewClient`的`onReceivedSslError`方法时，避免调用`proceed`忽略证书验证错误信息继续加载页面。

#### 3.1.3 漏洞代码示例

![image](https://github.com/tianyalu/NeAppNetworkSecurity/raw/master/show/unsafe_http_connection_code.png)

#### 3.1.4 `https`抓包分析

抓包工具抓包时，给目标设备安装并信任抓包工具的自签名证书，这时候就可以分析`https`请求了，下面是正常抓`https`请求的包和配置过证书后的抓包：

![image](https://github.com/tianyalu/NeAppNetworkSecurity/raw/master/show/https_packet_capture.png)

### 3.2 安全措施

* 代码混淆加固：防止反编译泄漏通讯秘钥及协议算法；
* 漏洞扫描：发布产品前对`app`进行漏洞扫描，提前预防网络传输漏洞；
* 核心算法`native`化：核心逻辑，比如加密算法、秘钥生成、协议字段组装放`jni`层实现；
* 使用`Socket`连接：走`TCP/UDP`，对抗`Fiddler`、`Charles`等抓包工具。