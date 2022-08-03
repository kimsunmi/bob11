#include <stdio.h> 
#include <openssl/bn.h>

BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *s1 = BN_new();
        BIGNUM *s2 = BN_new();
        BIGNUM *t1 = BN_new();
        BIGNUM *t2 = BN_new();
        BIGNUM *r1 = BN_new();
        BIGNUM *r2 = BN_new();
        BIGNUM *q = BN_new();
        BIGNUM *tmp = BN_new();
        int flag=0;

        BN_copy(r1,a);
        BN_copy(r2,b);
        BN_dec2bn(&s1,"1");
        BN_dec2bn(&s2, "0");
        BN_dec2bn(&t1, "0");
        BN_dec2bn(&t2, "1");

        while (1){
                BN_div(q,r1,r1,r2,ctx);
                if (BN_is_zero(r1)){
                        BN_copy(x,s2);
                        BN_copy(y,t2);
                        if(s1 != NULL) BN_free(s1);
                        if(s2 != NULL) BN_free(s2);
                        if(t1 != NULL) BN_free(t1);
                        if(t2 != NULL) BN_free(t2);
                        if(r1 != NULL) BN_free(r1);
                        if(q != NULL) BN_free(q);
                        if(tmp != NULL) BN_free(tmp);
                        if(ctx != NULL) BN_CTX_free(ctx);
                        return r2;
                }
                BN_mul(tmp,s2,q,ctx);
                BN_sub(s1,s1,tmp);
                BN_swap(s1,s2);

                BN_mul(tmp,t2,q,ctx);
                BN_sub(t1,t1,tmp);
                BN_swap(t1,t2);

                BN_swap(r1,r2);

        }
}

void printBN(char *msg, BIGNUM * a)
{
        char * number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);
}
int main (int argc, char *argv[])
{
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();
        BIGNUM *gcd;

        if(argc != 3){
                printf("usage: xeuclid num1 num2");
                return -1;
        }
        BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&b, argv[2]);
        gcd = XEuclid(x,y,a,b);
        printBN("(a,b) = ", gcd);
        printBN("a = ", a);
        printBN("b = ", b);
        printBN("x = ", x);
        printBN("y = ", y);
        printf("%s*(%s) + %s*(%s) = %s\n",BN_bn2dec(a),BN_bn2dec(x),BN_bn2dec(b),BN_bn2dec(y),BN_bn2dec(gcd));

        if(a != NULL) BN_free(a);
        if(b != NULL) BN_free(b);
        if(x != NULL) BN_free(x);
        if(y != NULL) BN_free(y);
        if(gcd != NULL) BN_free(gcd);

        return 0;
}
