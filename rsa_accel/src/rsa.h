#ifndef RSA_H
#define RSA_H

#include "rsa_int.h"
#include "rsa_seq_def.h"
#include <fstream>

typedef RSAInt<MAX_RSA_BITS> RSAFullInt;
typedef RSAInt<MAX_RSA_BITS> RSAPrimeInt;
typedef RSAFullInt RSAModulus;
typedef RSAFullInt RSAPublicExponent;
typedef RSAFullInt RSAPrivateExponent;
typedef RSAFullInt RSAMessage;
typedef RSAFullInt RSAPrime;

struct RSAKeyParser
{
    enum FileType {
        base64,
        asn1,
        decoded
    };
    
    RSAKeyParser(const std::string& file_name, FileType file_type);
    ~RSAKeyParser();

    void open(const std::string& file_name, FileType file_type);
    void close();
    
    std::string read_line();
    uint32_t read_asn1_length();
    
    void open_sequence();
    void close_sequence();
    
    RSAFullInt get_integer();

    std::istream* file_stream;
    FileType file_type;
};

struct RSAPublicKey
{
    RSAModulus modulus;
    RSAPublicExponent publicExponent;
};

struct RSAPrivateKey
{
    RSAPrivateKey();
    RSAPrivateKey(const std::string& file_name, RSAKeyParser::FileType file_type);
    
    RSAModulus modulus; // mod
    RSAPublicExponent publicExponent; // e
    RSAPrivateExponent privateExponent; // d
    RSAPrimeInt prime1, prime2; // p, q
    RSAPrimeInt exponent1, exponent2; // dP, dQ
    RSAPrimeInt coefficient; // qInv
};

inline
RSAPublicKey RSAGetPublicKey(const RSAPrivateKey& key)
{
    RSAPublicKey ret;
    ret.modulus = key.modulus;
    ret.publicExponent = key.publicExponent;
    return ret;
}

inline
RSAPublicKey RSAGetPrivateKeyAsPublic(const RSAPrivateKey& key)
{
    RSAPublicKey ret;
    ret.modulus = key.modulus;
    ret.publicExponent = key.privateExponent;
    return ret;
}

RSAMessage RSAEP(const RSAMessage& m, const RSAPublicKey& public_key);

double get_time();

#endif
