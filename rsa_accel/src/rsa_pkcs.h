#ifndef RSA_PKCS_DEF_H
#define RSA_PKCS_DEF_H

// Padding definitions, taken from $OPENSSL_DIR/include/openssl/rsa.h
# define RSA_PKCS1_PADDING       1
# define RSA_SSLV23_PADDING      2
# define RSA_NO_PADDING          3
# define RSA_PKCS1_OAEP_PADDING  4
# define RSA_X931_PADDING        5
/* EVP_PKEY_ only */
# define RSA_PKCS1_PSS_PADDING   6
# define RSA_PKCS1_PADDING_SIZE  11


int rsa_pkcs_public_encrypt (      RSAMessage,  RSAMessage&, const RSAPrivateKey&, int);
int rsa_pkcs_private_encrypt(      RSAMessage,  RSAMessage&, const RSAPrivateKey&, int, bool const);
int rsa_pkcs_public_decrypt (const RSAMessage&, RSAMessage&, const RSAPrivateKey&, int);
int rsa_pkcs_private_decrypt(      RSAMessage,  RSAMessage&, const RSAPrivateKey&, int, bool const);

int rsa_pkcs_private_encrypt_packet(std::vector<RSAMessage>&, std::vector<RSAMessage>&, std::vector<const RSAPrivateKey*>&, size_t, int, bool const);

#endif // RSA_PKCS_DEF_H
