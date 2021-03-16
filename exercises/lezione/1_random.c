#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>

#define MAX_BUF 2048

int main(int argc, char** argv){

    int n=0;

    unsigned char random_string[MAX_BUF];

    if(argc < 2){
        fprintf(stderr, "Errore parametri\n");
        exit(1);
    }

    n = atoi(argv[1]);

    //init the random generator
    int rc = RAND_load_file("/dev/random", 32);   //seed
    if(rc != 32){
        fprintf(stderr, "Errore seed\n");
        exit(1);
    }

    //generatte the random byte
    RAND_bytes(random_string, n);   //genero n byte random

    printf("Sequenza generata: ");
    for(int i=0; i<n; i++){
        printf("%x", random_string[i]);
    }
    printf("\n");
    
}