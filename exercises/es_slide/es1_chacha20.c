#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>

#define MAX_BUFF 1024

void handleErrors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char** argv){

    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char outbuf[MAX_BUFF];
    unsigned char decbuf[MAX_BUFF];
    unsigned char *message = (unsigned char *) "questo e un messaggio";
    int key_len, iv_len, olen, tlen, tot_dec;

    ERR_load_crypto_strings();

    OpenSSL_add_all_algorithms();

    key_len = EVP_CIPHER_key_length(EVP_chacha20());
    if(key_len==-1)
        handleErrors();

    iv_len = EVP_CIPHER_iv_length(EVP_chacha20());
    if(iv_len==-1)
        handleErrors();

    int rc = RAND_load_file("/dev/random", 32);
    if(rc!=32){
        fprintf(stderr, "Errore PRNG\n");
        exit(1);
    }

    printf("Key length = %d, IV length = %d\n", key_len, iv_len);

    RAND_bytes(key, key_len);
    RAND_bytes(iv, iv_len);

    printf("Key = ");
    for(int i=0; i<key_len; i++){
        printf("%x", key[i]);
    }
    printf("\n");

    printf("IV = ");
    for(int i=0; i<iv_len; i++){
        printf("%x", iv[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    if(1 != EVP_CipherInit_ex(ctx, EVP_chacha20(), NULL, key, iv, 1))
        handleErrors();

    printf("message = %s\n", message);

    //encryption
    int tot=0;
    if(1 != EVP_CipherUpdate(ctx, outbuf, &olen, message, strlen(message)))
        handleErrors();

    tot+=olen;

    if(1 != EVP_CipherFinal_ex(ctx, outbuf+tot, &tlen))
        handleErrors();

    tot+=tlen;

    printf("Ciphertext = ");
    for(int i=0; i<tot; i++){
        printf("%x", outbuf[i]);
    }
    printf("\n");

    //decryption
    tot_dec=0; olen=0; tlen=0;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_CipherInit_ex(ctx, EVP_chacha20(), NULL, key, iv, 0);

    if(1 != EVP_CipherUpdate(ctx, decbuf, &olen, outbuf, tot))
        handleErrors();

    tot_dec+=olen;

    if(1 != EVP_CipherFinal_ex(ctx, decbuf+tot_dec, &tlen))
        handleErrors();

    printf("message = %s\n", decbuf);

    EVP_cleanup();

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return 0;
}