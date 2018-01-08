/**
 * Password encoding protection.
 * @Author cjiang (changhao.jiang@taurus.ai)
 * @since   Jan, 2018
 *  this file should not be open-sourced !!!
 *
 *  if cryptopp is not here, following steps may help
 *      mkdir -p /shared/kungfu/tmp
 *      cd /shared/kungfu/tmp
 *      wget https://github.com/weidai11/cryptopp/archive/CRYPTOPP_5_6_5.tar.gz
 *      tar -xvf CRYPTOPP_5_6_5.tar.gz && cd cryptopp-CRYPTOPP_5_6_5 && make && make install
 *      cd .. && rm -rf CRYPTOPP_5_6_5.tar.gz cryptopp-CRYPTOPP_5_6_5
 */

#ifndef YIJINJING_ACTIVATION_CODE_H
#define YIJINJING_ACTIVATION_CODE_H

#include <iostream>
using std::ostream;
using std::cout;
using std::cerr;
using std::endl;
using std::ios;

#include <string>
using std::string;

#include "cryptlib.h"
using CryptoPP::lword;
//using CryptoPP::byte;
using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::Exception;

#include "secblock.h"
using CryptoPP::SecByteBlock;
using CryptoPP::SecBlock;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::HashVerificationFilter;
using CryptoPP::HashFilter;

#include "files.h"
using CryptoPP::FileSink;

#include "sha.h"
using CryptoPP::SHA256;
using CryptoPP::SHA512;

#include "aes.h"
using CryptoPP::AES;

#include "modes.h"
using CryptoPP::CBC_Mode;

#include "pwdbased.h"
#include "hmac.h"
using CryptoPP::HMAC;

#define MASTER_KEY "zhongtai"
#define SALT_KEY "D9AE6BD6BECB52F3088791D0A5B"
#define ITERATION_NUMBER 100
#define PREFIX "Kungfu"
#define DELIMITER "@"
#define ALLPREFIX PREFIX DELIMITER

void DeriveKeyAndIV(const string& master, const string& salt,
                    unsigned int iterations,
                    SecByteBlock& ekey, unsigned int eksize,
                    SecByteBlock& iv, unsigned int vsize,
                    SecByteBlock& akey, unsigned int aksize)
{
    using CryptoPP::PKCS5_PBKDF2_HMAC;
    SecByteBlock tb, ts(SHA512::DIGESTSIZE), tm(SHA512::DIGESTSIZE);

    // Temporary salt, stretch size.
    SHA512 hash;
    hash.CalculateDigest(ts, (const byte*)salt.data(), salt.size());

    static const string s1 = "master key";
    tb = SecByteBlock((const byte*)master.data(), master.size()) + SecByteBlock((const byte*)s1.data(), s1.size());

    PKCS5_PBKDF2_HMAC<SHA512> pbkdf;
    const byte unused = 0;
    pbkdf.DeriveKey(tm, tm.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    100);

    static const string s2 = "encryption key";
    ekey.resize(eksize);
    tb = tm + SecByteBlock((const byte*)s2.data(), s2.size());
    pbkdf.DeriveKey(ekey, ekey.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    100);

    static const string s3 = "initialization vector";
    iv.resize(vsize);
    tb = tm + SecByteBlock((const byte*)s3.data(), s3.size());
    pbkdf.DeriveKey(iv, iv.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    100);

    static const string s4 = "authentication key";
    akey.resize(aksize);
    tb = tm + SecByteBlock((const byte*)s4.data(), s4.size());
    pbkdf.DeriveKey(akey, iv.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    100);
}

void PrintKeyAndIV(SecByteBlock& ekey,
                   SecByteBlock& iv,
                   SecByteBlock& akey)
{
    // Print them
    HexEncoder encoder(new FileSink(cout));

    cout << "AES key: ";
    encoder.Put(ekey.data(), ekey.size());
    encoder.MessageEnd(); cout << endl;

    cout << "AES IV: ";
    encoder.Put(iv.data(), iv.size());
    encoder.MessageEnd(); cout << endl;

    cout << "HMAC key: ";
    encoder.Put(akey.data(), akey.size());
    encoder.MessageEnd(); cout << endl;
}

std::string hexDecode(const string& hexString)
{
    string decoded;
    HexDecoder decoder;
    decoder.Put( (byte*)hexString.data(), hexString.size() );
    decoder.MessageEnd();
    std::cout << decoded << std::endl;
    word64 size = decoder.MaxRetrievable();
    if(size && size <= SIZE_MAX)
    {
        decoded.resize(size);
        decoder.Get((byte*)decoded.data(), decoded.size());
    }
    return decoded;
}

void printEncode(const string& input)
{
    SecByteBlock ekey(16), iv(16), akey(16);

    DeriveKeyAndIV(MASTER_KEY, SALT_KEY, ITERATION_NUMBER,
                   ekey, ekey.size(), iv, iv.size(), akey, akey.size());
    //encryptor
    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(ekey, ekey.size(), iv, iv.size());

    HMAC< SHA256> hmac1;
    hmac1.SetKey(akey, akey.size());
    HMAC< SHA256> hmac2;
    hmac2.SetKey(akey, akey.size());

    // Encrypt and authenticate data
    string cipher;
    StringSource ss1(input, true /*pumpAll*/, new StreamTransformationFilter(encryptor, new HashFilter(hmac1, new StringSink(cipher), true /*putMessage*/)));
    PrintKeyAndIV(ekey, iv, akey);
    cout << "InputMsg: " << input << endl;
    cout << "Encoded: " << ALLPREFIX;
    HexEncoder encoder(new FileSink(cout));
    encoder.Put((byte*)cipher.data(), cipher.size());
    encoder.MessageEnd();
    cout << endl;
}

std::string decodeMsg(const string& encoded)
{
    if (strncmp(encoded.c_str(), ALLPREFIX, strlen(ALLPREFIX)) != 0)
        return encoded;
    string code = encoded.substr(encoded.find(DELIMITER) + 1);
    SecByteBlock ekey(16), iv(16), akey(16);
    DeriveKeyAndIV(MASTER_KEY, SALT_KEY, ITERATION_NUMBER, ekey, ekey.size(), iv, iv.size(), akey, akey.size());

    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(ekey, ekey.size(), iv, iv.size());

    HMAC< SHA256> hmac1;
    hmac1.SetKey(akey, akey.size());
    HMAC< SHA256> hmac2;
    hmac2.SetKey(akey, akey.size());
    string decoded = hexDecode(code);
    string recover;
    // Authenticate and decrypt data
    static const word32 flags = CryptoPP::HashVerificationFilter::HASH_AT_END |
                                CryptoPP::HashVerificationFilter::PUT_MESSAGE |
                                CryptoPP::HashVerificationFilter::THROW_EXCEPTION;
    StringSource ss2(decoded, true /*pumpAll*/, new HashVerificationFilter(hmac2, new StreamTransformationFilter(decryptor, new StringSink(recover)), flags));
    // parse decrypted message, format: email|expiredTime eg "user@email.com|20170522-10:00:00"
    return recover;
}

#endif //YIJINJING_ACTIVATION_CODE_H
