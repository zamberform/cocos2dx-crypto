//
//  CCCryptoUtil.hpp
//  CryptSample
//
//  Created by brightzamber on 2016/04/15.
//
//

#ifndef CCCryptoUtil_hpp
#define CCCryptoUtil_hpp

#include <stdio.h>

namespace cocos2djun {
    
    enum CCCryptoMode {
        COCOS_DES = 1,
        COCOS_DES2 = 2,
        COCOS_DES3 = 3,
        COCOS_AES = 4
    };
    
    class CCCryptoUtil {
        
    private:
        int crypto_type;
        int crypto_length;
        
    private:
        std::string base64Enc(std::string strSrc);
        std::string base64Dec(std::string strSrc);
    
    public:
        CCCryptoUtil();
        virtual ~CCCryptoUtil();
        
        //key&mode init
        void init(std::string key, int type);
        
        //set crypto mode
        bool encryptResource(std::string inputPath, std::string outputPath);
        bool decryptResource(std::string inputPath, std::string outputPath);
        std::vector<char> decryptResourceStream(std::string inputPath);
        std::string encryptString(std::string inputStr);
        std::string decryptString(std::string inputStr);
        
        //other help method
        std::string md5StrInfo(std::string inputStr);
        std::string md5FileInfo(std::string filePath);
        
        //Base64
        std::string fileBase64Enc(std::string strFileName);
        void fileBase64Dec(std::string strBase64, std::string strFileName);
    };
    
}
#endif /* CCCryptoUtil_hpp */
