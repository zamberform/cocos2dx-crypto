cocos2dx-encrypt
================

encrypt tools with cocos2dx

I hava completed ios and android encrypt tools for cocos2dx with openssl

but I think there will hava good method to make encryption by C++

## Encrypt with DES,DES2,DES3,AES

you can encryot file with cryto tools like pycrypt or nodejs crypto

## Decrypto in cocos2dx

complete decrypto system in cocos2dx

for example:

write with AES

{% highlight ruby %}

// init the file system with decrypt code
FileUtils::getInstance()->createCryptoSystem("1234567890123456", 4);
// decrypto the encrypt file in sprite
auto sprite = Sprite::createCrypto("res/HelloWorldTest.png");

{% endhighlight %}


also you can rewrite with 2d&3d parts

## you can learn more about in [there](http://zamberform.github.io/memos/cocos2dx/2016/12/11/cocos2dx-crypto.html)