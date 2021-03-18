#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <string.h>

#define MAX_BUF 1024
#define KEY "deadbeefdeadbeef"

void handleErrors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char** argv){

    unsigned char digest[EVP_MAX_MD_SIZE], buff[MAX_BUF];
    int n, md_len;

    FILE *fin;

    if(argc < 2){
        printf("Please give a filename to compute the HMAC on\n");
        return 1; 
    }

    fin = fopen(argv[1], "r");
    if(fin == NULL){
        printf("Errore file input\n");
        return 1;
    }

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    
    HMAC_CTX *hmac_ctx;
    hmac_ctx = HMAC_CTX_new();
    if(hmac_ctx == NULL)
        handleErrors();

    if(1!=HMAC_Init_ex(hmac_ctx,KEY,strlen(KEY),EVP_sha512(),NULL))
        handleErrors();

    while((n=fread(buff, 1, MAX_BUF, fin)) > 0){
        if(1!=HMAC_Update(hmac_ctx, buff, n))
            handleErrors();
    }

    if(1!=HMAC_Final(hmac_ctx, digest, &md_len)){
        handleErrors();
    }

    HMAC_CTX_free(hmac_ctx);

    printf("The MAC is: ");
        for(int i = 0; i < md_len; i++)
          printf("%x", digest[i]);
        printf("\n");

    CRYPTO_cleanup_all_ex_data();

    EVP_cleanup();

    ERR_free_strings();

    return 0;
}