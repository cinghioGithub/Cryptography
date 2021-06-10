#include <stdio.h>
#include <string.h>
#include </usr/include/stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define ERR_SIZE 130

int main(int argc, char **argv)
{
    unsigned char key[128];
    int key_size;
    char *pri_key, *pub_key;
    size_t pri_len, pub_len; 
    char err[ERR_SIZE];   
    //se le chiavi non ci sono

    RSA *rsa_keypair = NULL;
    BIGNUM *bne = NULL;

    int bits = 2048;
    unsigned long e = RSA_F4;

    // 1. generate the RSA key
    bne = BN_new();
    if (!BN_set_word(bne, e))
    {
        goto free_all;
    }

    rsa_keypair = RSA_new();
    /* callback not needed for our purposes */
    if (!RSA_generate_key_ex(rsa_keypair, bits, bne, NULL))
    {
        goto free_all;
    }
    //fine

    BIO *pri_bio = BIO_new(BIO_s_mem());
    BIO *pub_bio = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri_bio, rsa_keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub_bio, rsa_keypair);

    //count the character actually written into the BIO object
    pri_len = BIO_pending(pri_bio);./
    pub_len = BIO_pending(pub_bio);

    // allocate a standard string
    pri_key = (char *)malloc(pri_len + 1); //room for the '\0'
    pub_key = (char *)malloc(pub_len + 1); //room for the '\0'

    BIO_read(pri_bio, pri_key, pri_len);
    BIO_read(pub_bio, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    int rc = RAND_load_file("/dev/random", 32);
    if (rc != 32)
    {
        fprintf(stderr, "Couldnt initialize the PRNG\n");
        exit(-4);
    }
    RAND_bytes(key, 16);

    printf("Random key: %s", key);

    char *encrypted_data = NULL; // Encrypted message
    int encrypted_data_len;

    // int RSA_size(const RSA *rsa);
    encrypted_data = (char *)malloc(RSA_size(rsa_keypair));

    if ((encrypted_data_len = RSA_public_encrypt(strlen(key) + 1, (unsigned char *)key,
                                                 (unsigned char *)encrypted_data,
                                                 rsa_keypair, RSA_PKCS1_OAEP_PADDING)) == -1)
    {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
        goto free_allocated_memory;
    }

    char *decrypted_data; // Decrypted message
    decrypted_data = (char *)malloc(encrypted_data_len);

    /*
        int RSA_private_decrypt(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding);
        Error management is the same and the _encrypt function
    */

    if (RSA_private_decrypt(encrypted_data_len, (unsigned char *)encrypted_data,
                            (unsigned char *)decrypted_data,
                            rsa_keypair, RSA_PKCS1_OAEP_PADDING) == -1)
    {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
        goto free_allocated_memory;
    }
    printf("Decrypted message: %s\n", decrypted_data);

free_all:

    //BIO_free_all(bp_public);
    //BIO_free_all(bp_private);
    RSA_free(rsa_keypair);
    BN_free(bne);
    return 0;

free_allocated_memory:
    RSA_free(rsa_keypair);
    BIO_free_all(pub_bio);
    BIO_free_all(pri_bio);
    free(pri_key);
    free(pub_key);
    free(encrypted_data);
    free(decrypted_data);
    return 0;
}
