'use strict'; 
var crypto = require("crypto");

var planeText = 'abcd';
var passowrd = '1234567890123456';

console.log('暗号化するテキスト : ' + planeText);
console.log('暗号化キー        : ' + passowrd);

// 暗号化
var cipher = crypto.createCipheriv('aes128', passowrd, passowrd);
cipher.update(planeText, 'utf8', 'hex');
var cipheredText = cipher.final('hex');

console.log('暗号化(AES128) :');
console.log(cipheredText);

// 復号
var decipher = crypto.createDecipheriv('aes128', passowrd, passowrd);
decipher.update(cipheredText, 'hex', 'utf-8');
var dec = decipher.final('utf8');

console.log('復号化(AES128) : ');
console.log(dec);

var data = "abcd";
var key = new Buffer('1234567890123456');
var iv = new Buffer('1234567890123456');
var cipher = crypto.createCipheriv('aes128', key, iv);
var encrypted = cipher.update(data, 'utf-8', 'hex');
var cipheredText = cipher.final('hex');
// encrypted = Buffer.concat([iv, encrypted, cipher.final()]);
console.log( cipheredText );
