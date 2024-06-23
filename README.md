# The cfcrypt tool
This tool is used for encrypting and decrypting files (encrypted by this program).

## Usage:
```console
cfcrypt [PARAMS] -i input.txt -o output.txt
PARAMETERS:
-m MODE         Mode, can be either encrypt or decrypt
-a ALGO         Algorithms, possible values: aes128, aes192, aes256
-k KEY          Input Key, requried for decrypting, for encryption it will generate if not provided for encryption
-p pass         Encrypt using a password
Note: -p and -k can't be used together
```
### Example: Encrypting / Decrypting a file using password with AES-128
```console
honey@HONEY-PC:~/projects/cfcrypt/build$ cat TestFile123.txt 
This is a sample text file.
We can encrypt this and then decrypt to see if this is done correctly.
honey@HONEY-PC:~/projects/cfcrypt/build$ ./cfcrypt -m encrypt -a aes128 -i TestFile123.txt -o TestFile123.txt.enc -p ADemoPassword
File encrypted successfully to: TestFile123.txt.enc
Note: TestFile123.txt is not deleted.
honey@HONEY-PC:~/projects/cfcrypt/build$ hexdump TestFile123.txt
0000000 6854 7369 6920 2073 2061 6173 706d 656c
0000010 7420 7865 2074 6966 656c 0a2e 6557 6320
0000020 6e61 6520 636e 7972 7470 7420 6968 2073
0000030 6e61 2064 6874 6e65 6420 6365 7972 7470
0000040 7420 206f 6573 2065 6669 7420 6968 2073
0000050 7369 6420 6e6f 2065 6f63 7272 6365 6c74
0000060 2e79 000a                              
0000063
honey@HONEY-PC:~/projects/cfcrypt/build$ hexdump TestFile123.txt.enc
0000000 1c6b 43d6 f099 84f6 f3eb 855f 0526 a410
0000010 483f d75e 101e 991a 68cf 20d0 a239 a4d8
0000020 9262 657f a9d1 a50e 6e12 ec1d 3cca 3157
0000030 5d9a c60c 9a4c fcf4 5d2c dca2 1947 f084
0000040 7440 27b8 888b 2667 da29 9871 0c28 a8fb
0000050 363f 8880 ad37 24a9 90e5 630f d384 29cf
0000060 5f0f 4f8a 50b1 2d1b bd41 45f3 b547 52d8
0000070 21a0 d85e a050 3c53 5c29 9275 372b 853d
0000080 178f feb7 8b2b 0ba0 4872 d0b2 6bba 46c9
0000090
honey@HONEY-PC:~/projects/cfcrypt/build$ ./cfcrypt -m decrypt -a aes128 -i TestFile123.txt.enc -o TestFile123.txt.dec -p ADemoPassword
File decrypted successfully to: TestFile123.txt.dec
Note: TestFile123.txt.enc is not deleted.
honey@HONEY-PC:~/projects/cfcrypt/build$ hexdump TestFile123.txt.dec
0000000 6854 7369 6920 2073 2061 6173 706d 656c
0000010 7420 7865 2074 6966 656c 0a2e 6557 6320
0000020 6e61 6520 636e 7972 7470 7420 6968 2073
0000030 6e61 2064 6874 6e65 6420 6365 7972 7470
0000040 7420 206f 6573 2065 6669 7420 6968 2073
0000050 7369 6420 6e6f 2065 6f63 7272 6365 6c74
0000060 2e79 000a                              
0000063
honey@HONEY-PC:~/projects/cfcrypt/build$ cat TestFile123.txt.dec
This is a sample text file.
We can encrypt this and then decrypt to see if this is done correctly.
honey@HONEY-PC:~/projects/cfcrypt/build$ diff TestFile123.txt TestFile123.txt.dec
```
