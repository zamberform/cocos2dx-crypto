from Crypto.Cipher import AES
import os
import binascii
import sys, getopt
from Crypto import Random

BS = AES.block_size
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
EncodeAES = lambda c, s: c.encrypt(pad(s))
unpad = lambda s: s[0:-ord(s[-1])]

def encrypt(message, key, key_size=16):
    cipher = AES.new(key, AES.MODE_CBC, key)
    return binascii.hexlify(cipher.encrypt(pad(message)))

def decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, key)
    plaintext = cipher.decrypt(binascii.unhexlify(ciphertext[AES.block_size:]))
    return plaintext

def encrypt_file(input_file_name, output_file_name, key):
    with open(input_file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(output_file_name, 'wb') as fo:
        fo.write(enc)

def decrypt_file(input_file_name, output_file_name, key):
    with open(input_file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    with open(output_file_name, 'wb') as fo:
        fo.write(dec)

def main(argv):
   inputInfo = ''
   outputInfo = ''
   key = None
   mode = True
   encryptFlg = True
   try:
      opts, args = getopt.getopt(argv,"i:o:p:hfd",["ifile=","ofile=","password=",'help','file','decrypt'])
   except getopt.GetoptError:
      print 'please input with -i <input> -o <output> -p <password> f <is file flag> d <d:decrypt, e:encrypt>'
      sys.exit(2)
   for opt, arg in opts:
      if opt in ('-h', '--help'):
         print 'please input with -i <input> -o <output> -p <password> -f <is file flag> -d <d:decrypt, e:encrypt>'
         sys.exit()
      elif opt in ("-i", "--ifile"):
         inputInfo = arg
      elif opt in ("-o", "--ofile"):
         outputInfo = arg
      elif opt in ("-p", "--password"):
         key = arg
      elif opt in ('-f', '--file'):
         mode = False
      elif opt in ('-d', '--decrypt'):
         encryptFlg = False


   if len(key) != 16:
        print 'please input password in 16 length'
   elif mode:
       if encryptFlg:
            print encrypt(inputInfo, key)
       else :
            print decrypt(inputInfo, key)
   else :
       if encryptFlg:
            encrypt_file(inputInfo, outputInfo, key)
       else:
            decrypt_file(inputInfo, outputInfo, key)



if __name__ == "__main__":
   main(sys.argv[1:])
