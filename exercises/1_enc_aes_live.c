#include <stdio.h>
#include <openssl/evp.h>
#include </usr/include/stdlib.h>

#define ENCRYPT 1
#define DECRYPT 0

#define BUF_SIZE 1024

int main(int argc, char **argv){

    unsigned char ibuf[BUF_SIZE], obuf[BUF_SIZE];

    int key_size,ilen,olen,tlen;

    //key
    unsigned char *key = (unsigned char *) "0123456789012345";

    //iv
    unsigned char *iv = (unsigned char *) "aaaaaaaaaaaaaaaaa";

    key_size = EVP_CIPHER_key_length(EVP_aes_128_cbc());

    EVP_CIPHER_CTX *ctx;     //context

    ctx = EVP_CIPHER_CTX_new();     //create the context

    EVP_CIPHER_CTX_init(ctx);   //inistiailsation of the context

    //plugin aes-128-cbc
    //use this key
    //use this iv
    //use this ENGINE
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, ENCRYPT);

    unsigned char *message = (unsigned char *) "this is message";

    int tot=0;
    //char obaf[2048]
    EVP_CipherUpdate(ctx, obuf, &olen, message, strlen(message));
    printf("olne = %d\n", olen);
    tot += olen;
    //for exaple the padding will be added after the text (+tot)
    EVP_CipherFinal_ex(ctx, obuf+tot, &olen);
    tot += olen;

    printf("olne = %d\n", tot);

    ctx = EVP_CIPHER_CTX_new();      //it is better to redefine a new context

    EVP_CIPHER_CTX_init(ctx);  

    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, DECRYPT);

    int tot_dec=0;
    unsigned char decrypt[BUF_SIZE];
    //char obaf[2048]
    EVP_CipherUpdate(ctx, decrypt, &olen, obuf, strlen(message));
    printf("olne = %d\n", olen);
    tot_dec += tlen;
    //for exaple the padding will be added after the text (+tot)
    EVP_CipherFinal_ex(ctx, decrypt+tot_dec, &tlen);
    tot += olen;

    printf("olne = %d\n", tot_dec);

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}