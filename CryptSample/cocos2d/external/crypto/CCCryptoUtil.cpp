//
//  CCCryptoUtil.cpp
//  CryptSample
//
//  Created by brightzamber on 2016/04/15.
//
//

#include "CCCryptoUtil.hpp"
#include <iostream>
#include <iomanip>

#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/des.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"
#include "cryptopp/md5.h"
#include "cryptopp/hex.h"
#include "cryptopp/base64.h"

using namespace cocos2djun;
using namespace CryptoPP;
using namespace std;

string cryptokey;
string cryptoiv;

CCCryptoUtil::CCCryptoUtil(){
    
}

CCCryptoUtil::~CCCryptoUtil(){
    cryptokey.clear();
}

void CCCryptoUtil::init(std::string key, int type){
    crypto_type = type;
    switch (type) {
        case COCOS_DES:
            crypto_length = DES::DEFAULT_KEYLENGTH;
            cryptokey = key;
//            memcpy( &cryptokey, key.c_str(), DES::DEFAULT_KEYLENGTH );
            break;
        case COCOS_DES2:
            crypto_length = DES_EDE2::DEFAULT_KEYLENGTH;
            cryptokey = key;
//            memcpy( &cryptokey, key.c_str(), DES_EDE2::DEFAULT_KEYLENGTH );
            break;
        case COCOS_DES3:
            crypto_length = DES_EDE3::DEFAULT_KEYLENGTH;
            cryptokey = key;
//            memcpy( &cryptokey, key.c_str(), DES_EDE3::DEFAULT_KEYLENGTH );
            break;
        case COCOS_AES:
        {
            crypto_length = AES::DEFAULT_KEYLENGTH;
            cryptokey = key;
            cryptoiv = key;
//            memcpy( &cryptokey, key.c_str(), AES::DEFAULT_KEYLENGTH );
//            memcpy( &cryptoiv, key.c_str(), AES::BLOCKSIZE );
        }
            
            break;
        default:
            break;
    }
}

bool CCCryptoUtil::encryptResource(std::string inputPath, std::string outputPath){
    
    switch (crypto_type) {
        case COCOS_DES:
        {
            ECB_Mode<DES>::Encryption encctx( (byte*)cryptokey.c_str(), crypto_length );
            FileSource( inputPath.c_str(), true,
                       new StreamTransformationFilter(encctx,
                                                      new FileSink(outputPath.c_str()), BlockPaddingSchemeDef::PKCS_PADDING));
        }
            break;
        case COCOS_DES2:
        {
            CBC_Mode<DES_EDE2>::Encryption encctx;
            encctx.SetKey( (byte*)cryptokey.c_str(), crypto_length );
            FileSource( inputPath.c_str(), true,
                       new StreamTransformationFilter(encctx,
                                                      new FileSink(outputPath.c_str()), BlockPaddingSchemeDef::PKCS_PADDING));
        }
            break;
        case COCOS_DES3:
        {
            CBC_Mode<DES_EDE3>::Encryption encctx;
            encctx.SetKey( (byte*)cryptokey.c_str(), crypto_length );
            FileSource( inputPath.c_str(), true,
                       new StreamTransformationFilter(encctx,
                                                      new FileSink(outputPath.c_str()), BlockPaddingSchemeDef::PKCS_PADDING));
        }
            break;
        case COCOS_AES:
        {
            CBC_Mode<AES>::Encryption aesEncryption;
            aesEncryption.SetKeyWithIV((byte*)cryptokey.c_str(), crypto_length, (byte*)cryptoiv.c_str());
            
            FileSource(inputPath.c_str(), true,
                       new StreamTransformationFilter(aesEncryption,
                                                      new FileSink(outputPath.c_str()), BlockPaddingSchemeDef::PKCS_PADDING ));
        }
            break;
        default:
            
            break;
    }

    
    return true;
}

bool CCCryptoUtil::decryptResource(std::string inputPath, std::string outputPath){
    string decryptStream;
    switch (crypto_type) {
        case COCOS_DES:
        {
            ECB_Mode<DES>::Decryption decctx;
            decctx.SetKey( (byte*)cryptokey.c_str(), crypto_length );
            FileSource( inputPath.c_str(), true,
                       new StreamTransformationFilter( decctx,
                                                      new FileSink( outputPath.c_str() ),
                                                      BlockPaddingSchemeDef::PKCS_PADDING
                                                      )
                       );
        }
            break;
        case COCOS_DES2:
        {
            CBC_Mode<DES_EDE2>::Decryption decctx;
            decctx.SetKey( (byte*)cryptokey.c_str(), crypto_length );
            FileSource( inputPath.c_str(), true,
                       new StreamTransformationFilter(decctx,
                                                      new FileSink( outputPath.c_str() ),
                                                      BlockPaddingSchemeDef::PKCS_PADDING
                                                      )
                       );
        }
            break;
        case COCOS_DES3:
        {
            CBC_Mode<DES_EDE3>::Decryption decctx;
            decctx.SetKey( (byte*)cryptokey.c_str(), crypto_length );
            FileSource( inputPath.c_str(), true,
                       new StreamTransformationFilter(decctx,
                                                      new FileSink( outputPath.c_str() ),
                                                      BlockPaddingSchemeDef::PKCS_PADDING
                                                      )
                       );
        }
            break;
        case COCOS_AES:
        {
            CBC_Mode<AES>::Decryption aesDecryption;
            aesDecryption.SetKeyWithIV((byte*)cryptokey.c_str(), crypto_length, (byte*)cryptoiv.c_str());
            
            FileSource(inputPath.c_str(), true,
                       new StreamTransformationFilter(aesDecryption,
                                                      new FileSink( outputPath.c_str() ),
                                                      BlockPaddingSchemeDef::PKCS_PADDING)
                       );
        }
            break;
        default:
            
            break;
    }
    
    return true;
}

std::vector<char> CCCryptoUtil::decryptResourceStream(std::string inputPath){
    string decryptStream;
    switch (crypto_type) {
        case COCOS_DES:
        {
            ECB_Mode<DES>::Decryption decctx;
            decctx.SetKey( (byte*)cryptokey.c_str(), crypto_length );
            FileSource( inputPath.c_str(), true,
                       new StreamTransformationFilter( decctx,
                                                      new StringSink( decryptStream ),
                                                      BlockPaddingSchemeDef::PKCS_PADDING
                                                      )
                       );
        }
            break;
        case COCOS_DES2:
        {
            CBC_Mode<DES_EDE2>::Decryption decctx;
            decctx.SetKey( (byte*)cryptokey.c_str(), crypto_length );
            FileSource( inputPath.c_str(), true,
                       new StreamTransformationFilter(decctx,
                                                      new StringSink( decryptStream ),
                                                      BlockPaddingSchemeDef::PKCS_PADDING
                                                      )
                       );
        }
            break;
        case COCOS_DES3:
        {
            CBC_Mode<DES_EDE3>::Decryption decctx;
            decctx.SetKey( (byte*)cryptokey.c_str(), crypto_length );
            FileSource( inputPath.c_str(), true,
                       new StreamTransformationFilter(decctx,
                                                      new StringSink( decryptStream ),
                                                      BlockPaddingSchemeDef::PKCS_PADDING
                                                      )
                       );
        }
            break;
        case COCOS_AES:
        {
            CBC_Mode<AES>::Decryption aesDecryption;
            aesDecryption.SetKeyWithIV((byte*)cryptokey.c_str(), crypto_length, (byte*)cryptoiv.c_str());
            
            FileSource(inputPath.c_str(), true,
                       new StreamTransformationFilter(aesDecryption,
                                                      new StringSink( decryptStream ),
                                                      BlockPaddingSchemeDef::PKCS_PADDING)
                       );
        }
            break;
        default:
            
            break;
    }
    
    return { decryptStream.cbegin(), decryptStream.cend() };
}

std::string CCCryptoUtil::encryptString(std::string inputStr){
    string encoded;
    switch (crypto_type) {
        case COCOS_DES:
        {
            ECB_Mode<DES>::Encryption encctx( (byte*)cryptokey.c_str(), crypto_length );
            StringSource( inputStr, true,
                       new StreamTransformationFilter(encctx,
                                                      new HexEncoder(new StringSink(encoded)),
                                                      BlockPaddingSchemeDef::PKCS_PADDING)
                       );
        }
            break;
        case COCOS_DES2:
        {
            CBC_Mode<DES_EDE2>::Encryption encctx( (byte*)cryptokey.c_str(), crypto_length );
            StringSource( inputStr, true,
                         new StreamTransformationFilter(encctx,
                                                        new HexEncoder(new StringSink(encoded)),
                                                        BlockPaddingSchemeDef::PKCS_PADDING)
                         );
        }
            break;
        case COCOS_DES3:
        {
            CBC_Mode<DES_EDE3>::Encryption encctx( (byte*)cryptokey.c_str(), crypto_length );
            StringSource( inputStr, true,
                         new StreamTransformationFilter(encctx,
                                                        new HexEncoder(new StringSink(encoded)),
                                                        BlockPaddingSchemeDef::PKCS_PADDING)
                         );
        }
            break;
        case COCOS_AES:
        {
            CBC_Mode< AES >::Encryption encctx;
            encctx.SetKeyWithIV((byte*)cryptokey.c_str(), crypto_length, (byte*)cryptoiv.c_str());
            
            StringSource( inputStr, true,
                         new StreamTransformationFilter(encctx,
                                                        new HexEncoder(new StringSink(encoded)),
                                                        BlockPaddingSchemeDef::PKCS_PADDING)
                         );
            
        }
            break;
        default:
            
            break;
    }
    
    return encoded;
}

std::string CCCryptoUtil::decryptString(std::string inputStr){
    string encodeHexed;
    
    StringSource(inputStr, true,
                    new HexDecoder(
                                   new StringSink(encodeHexed)
                                   )
                    );
    
    string decryptString;
    switch (crypto_type) {
        case COCOS_DES:
        {
            ECB_Mode<DES>::Decryption decctx;
            decctx.SetKey( (byte*)cryptokey.c_str(), crypto_length );
            StringSource( encodeHexed, true,
                       new StreamTransformationFilter( decctx,
                                                      new StringSink( decryptString ),
                                                      BlockPaddingSchemeDef::PKCS_PADDING
                                                      )
                       );
        }
            break;
        case COCOS_DES2:
        {
            CBC_Mode<DES_EDE2>::Decryption decctx;
            decctx.SetKey( (byte*)cryptokey.c_str(), crypto_length );
            StringSource( encodeHexed, true,
                       new StreamTransformationFilter(decctx,
                                                      new StringSink( decryptString ),
                                                      BlockPaddingSchemeDef::PKCS_PADDING
                                                      )
                       );
        }
            break;
        case COCOS_DES3:
        {
            CBC_Mode<DES_EDE3>::Decryption decctx;
            decctx.SetKey( (byte*)cryptokey.c_str(), crypto_length );
            StringSource( encodeHexed, true,
                       new StreamTransformationFilter(decctx,
                                                      new StringSink( decryptString ),
                                                      BlockPaddingSchemeDef::PKCS_PADDING
                                                      )
                       );
        }
            break;
        case COCOS_AES:
        {
            CBC_Mode< AES >::Decryption aesDecryption;
            aesDecryption.SetKeyWithIV((byte*)cryptokey.c_str(), crypto_length, (byte*)cryptoiv.c_str());
            
            StringSource(encodeHexed, true,
                       new StreamTransformationFilter(aesDecryption,
                                                      new StringSink( decryptString ),
                                                      BlockPaddingSchemeDef::PKCS_PADDING)
                       );
        }
            break;
        default:
            
            break;
    }
    
    return decryptString;
}


//other help method
#pragma MD5
std::string CCCryptoUtil::md5StrInfo(std::string inputStr){
    string digest;
    Weak1::MD5 md5;
    StringSource(inputStr, true, new HashFilter(md5, new HexEncoder(new StringSink(digest))));
    return digest;
}

std::string CCCryptoUtil::md5FileInfo(std::string filePath){
    string digest;
    Weak1::MD5 md5;
    FileSource(filePath.c_str(), true, new HashFilter(md5,new HexEncoder(new StringSink(digest))));
    return digest;
}

string CCCryptoUtil::base64Enc(string strSrc)
{
    string strOut;
    StringSink* sink = new StringSink(strOut);
    Base64Encoder *base64Enc = new Base64Encoder(sink);
    StringSource source(strSrc, true, base64Enc);
    
    ssize_t iPos=-1;
    iPos = strOut.find("\n", 0);
    while(iPos>=0)
    {
        strOut = strOut.erase(iPos, 1);
        iPos = strOut.find("\n", 0);
    }
    
    return strOut;
}

string CCCryptoUtil::base64Dec(string strSrc)
{
    string strOut;
    StringSink *sink = new StringSink(strOut);
    Base64Decoder *baseDec = new Base64Decoder(sink);
    StringSource dst(strSrc, true, baseDec);
    return strOut;
}
#pragma Base64
string CCCryptoUtil::fileBase64Enc(string strFileName)
{
    string strBase64;
    
    string encode;
    FileSource(strFileName.c_str(), true, new Base64Encoder(new StringSink(encode)));
    strBase64 = encode;
    
    ssize_t iPos=-1;
    iPos = strBase64.find("\n", 0);
    while(iPos>=0)
    {
        strBase64 = strBase64.erase(iPos, 1);
        iPos = strBase64.find("\n", 0);
    }
    
    return strBase64;
}

void CCCryptoUtil::fileBase64Dec(string strBase64, string strFileName)
{
    FileSink *sink = new FileSink(strFileName.c_str());
    Base64Decoder *base64Dec = new Base64Decoder(sink);
    StringSource dst(strBase64, true, base64Dec);
}
