#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int main(int argc, char** argv){

    unsigned char key[EVP_MAX_KEY_LENGTH];
    FILE *out;
    int key_size;

    if(argc < 3){
        fprintf(stderr, "Errore parametri\n");
        exit(1);
    }

    out = fopen(argv[2], "w");
    if(out == NULL){
        fprintf(stderr, "Errore file output\n");
        exit(1);
    }

    const EVP_CIPHER *algo = EVP_get_cipherbyname(argv[1]);
    if(algo == NULL){
        fprintf(stderr, "Errore algoritmo\n");
        exit(1);
    }

    key_size = EVP_CIPHER_key_length(algo);

    int rc = RAND_load_file("/dev/random", 32);
    if(rc != 32){
        fprintf(stderr, "Errore seed\n");
        exit(1);
    }

    RAND_bytes( key, key_size );
    
    if(fwrite(key, 1, key_size, out) != key_size){
        fprintf(stderr, "Errore scrittura file\n");
        exit(1);
    }

    return 0;
}