#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>

int main(){
    BIGNUM *p=BN_new();
    BIGNUM *q=BN_new();
    BIGNUM *phi=BN_new();
    BIGNUM *n=BN_new();
    BIGNUM *one=BN_new();
    BIGNUM *e=BN_new();
    BIGNUM *d=BN_new();

    ERR_load_crypto_strings();

    if(!BN_set_word(one, 1)){
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    if(!BN_set_word(e, 65537)){
        ERR_print_errors_fp(stdout);
        exit(1);
    }


    int rc = RAND_load_file("/dev/random", 32);
    if(rc != 32){
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    if(!BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL)){
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    if(!BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL)){
        ERR_print_errors_fp(stdout);
        exit(1);
    }


    BN_CTX *ctx = BN_CTX_new();
    if(!BN_mul(n,p,q,ctx)){
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    if(!BN_sub(p, p, one)){
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    if(!BN_sub(q, q, one)){
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    if(!BN_mul(phi, p, q, ctx)){
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    if(!BN_set_word(one, -1)){
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    if(!BN_mod_exp(d, e, one, phi, ctx)){
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(phi);
    BN_free(one);
    BN_free(e);

    ERR_free_strings();

    return 0;
}