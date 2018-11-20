# 非对称加密（Asymmetric Cryptography）
非对称加密为数据的加密与解密提供了一个非常安全的方法，它使用了一对密钥，公钥（public key）和私钥（private key）。
私钥只能由一方安全保管，不能外泄，而公钥则可以发给任何请求它的人。
非对称加密使用这对密钥中的一个进行加密，而解密则需要另一个密钥。
比如，你向银行请求公钥，银行将公钥发给你，你使用公钥对消息加密，那么只有私钥的持有人--银行才能对你的消息解密。
与对称加密不同的是，银行不需要将私钥通过网络发送出去，因此安全性大大提高。
目前最常用的非对称加密算法是RSA算法，是Rivest, Shamir, 和Adleman于1978年发明。

![blockchain](https://ss0.bdstatic.com/70cFvHSh_Q1YnxGkpoWK1HF6hhy/it/
u=702257389,1274025419&fm=27&gp=0.jpg "区块链")

# 流程分析：
1.Bob构建密钥对儿，将公钥公布给Alice，将私钥保留。
2.Alice使用公钥加密数据，向Bob发送经过加密后的数据；Bob获得加密数据，通过私钥解密。反之亦然。

golang中也有RSA算法，请看下面的例子:

既然是非对称加密当然需要公钥和私钥，公钥私钥如何生成呢？请看下面示例：
