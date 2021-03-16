#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

void handleErrors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char** argv){

    FILE *fin;

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

    ERR_free_strings();
    ERR_free_strings();
    
    return 0;
}