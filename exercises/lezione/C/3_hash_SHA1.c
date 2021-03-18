#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <string.h>

#define MAX_BUF 1024

int main(int argc, char** argv){

    //printf("a");

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned char buff[MAX_BUF];

    //unsigned char *prova = (unsigned char *)"ciao come va\n";

    FILE *fin;
    int n, md_len;

    if(argc < 2){
        fprintf(stderr, "Errore parametri\n");
        exit(1);
    }

    //printf("a");

    fin = fopen(argv[1], "r");
    if(fin == NULL){
        fprintf(stderr, "Errore file\n");
        exit(1);
    }

    //printf("a");

    EVP_MD_CTX *ctx_md;
    ctx_md = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx_md, EVP_sha1(), NULL);

    while ((n=fread(buff, 1, MAX_BUF, fin)) > 0)
    {
        EVP_DigestUpdate(ctx_md, buff, n);
    }
    //EVP_DigestUpdate(ctx_md, prova, strlen(prova));

    EVP_DigestFinal_ex(ctx_md, digest, &md_len);

    EVP_MD_CTX_free(ctx_md);

    printf("Il digest è: ");
    for(int i=0; i<md_len; i++){
        printf("%x", digest[i]);
    }
    printf("\n");
    

    return 0;
}