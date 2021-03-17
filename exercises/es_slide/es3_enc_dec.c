#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>

#define MAX_BUF 1024

void handleErrors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char** argv){

    FILE *fin;
    const EVP_CIPHER *algo;
    int key_len, iv_len, n, olen, tlen, tot, tot_dec;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH], in[MAX_BUF], out[MAX_BUF], dec[MAX_BUF];

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if(argc < 3){
        fprintf(stderr, "Errore parametri\n");
        exit(1);
    }

    fin = fopen(argv[2], "r");
    if(fin == NULL){
        fprintf(stderr, "Errore file input\n");
        exit(1);
    }

    algo = EVP_get_cipherbyname(argv[1]);
    key_len = EVP_CIPHER_key_length(algo);
    iv_len = EVP_CIPHER_iv_length(algo);

    printf("Algorithm = %s\nKey length = %d\nIV length = %d\n", argv[1], key_len, iv_len);

    int rc = RAND_load_file("/dev/random", 32);
    if(rc != 32){
        fprintf(stderr, "Errore seed PRNG\n");
    }

    RAND_bytes(key, key_len);
    RAND_bytes(iv, iv_len);

    printf("KEY = ");
    for(int i=0; i<key_len; i++){
        printf("%x", key[i]);
    }
    printf("\n");

    printf("IV = ");
    for(int i=0; i<iv_len; i++){
        printf("%x", iv[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX *ctx, *ctx_dec;
    ctx = EVP_CIPHER_CTX_new();
    if(1 != EVP_CIPHER_CTX_init(ctx)){
        handleErrors();
    }

    if(1 != EVP_CipherInit_ex(ctx, algo, NULL, key, iv, 1)){
        handleErrors();
    }

    printf("Plain text = ");
    tot = 0;
    while((n=fread(in, 1, MAX_BUF, fin))>0){
        printf("%s", in);
        if(1 != EVP_CipherUpdate(ctx,out,&olen,in,n)){
            handleErrors();
        }
        //tot+=olen;
    }
    printf("\n");
    tot+=olen;

    EVP_CipherFinal_ex(ctx, out+olen, &tlen);
    tot+=tlen;

    printf("Cipher text = ");
    for(int i=0; i<tot; i++){
        printf("%x", out[i]);
    }
    printf("\n");

    ctx_dec = EVP_CIPHER_CTX_new();
    if(1!=EVP_CIPHER_CTX_init(ctx_dec)){
        handleErrors();
    }

    if(1!=EVP_CipherInit_ex(ctx_dec, algo, NULL, key, iv, 0)){
        handleErrors();
    }

    tot_dec=0;
    //olen=0;
    //tlen=0;
    if(1 != EVP_CipherUpdate(ctx_dec, dec, &olen, out, tot))
        handleErrors();

    tot_dec+=olen;

    if(1 != EVP_CipherFinal_ex(ctx_dec, dec+tot_dec, &tlen))
        handleErrors();

    tot_dec+=tlen;

    dec[tot_dec]='\0';
    printf("message = %s\n", dec);
    

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
    
    return 0;
}