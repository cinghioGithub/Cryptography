#include <stdio.h>
#include <openssl/rand.h>
#include <string.h>

#define MAX_BUF 2048

int main(int argc, char** argv){

    char random_string[MAX_BUF];

    int n = sscanf(argv[1], "%d", &n);

    int rc = RAND_load_file("/dev/random", 32);
    if(rc!=32){
        printf("Errore nel load_file\n");
        exit(1);
    }

    RAND_bytes(random_string, n);    //n is the integer conversion of argv[1]

    for(int i=0; i<strlen(random_string); i++)
        printf("%02x", (unsigned int) random_string[i]);

}