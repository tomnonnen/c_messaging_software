// ckvs_crypto

#include "ckvs.h"
#include "ckvs_crypto.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#define AUTH_MESSAGE "Auth Key"
#define C1_MESSAGE   "Master Key Encryption"



int generateAuthKeyStrechedKeyC1(ckvs_memrecord_t* mr, const char *key, const char *pwd){
    memset(mr, 0, sizeof(*mr)); //on le fait deja dans la func
    return ckvs_client_encrypt_pwd(mr,key,pwd);
}


int generateMasterKey(ckvs_memrecord_t* mr, ckvs_sha_t* c2){
    return  ckvs_client_compute_masterkey(mr, c2);
}





int encodeNewValue(ckvs_memrecord_t* mr,const char* newValue,unsigned char **outbuf, size_t* outputLength){
    unsigned char* encoded_newData = calloc(strlen(newValue)+EVP_MAX_BLOCK_LENGTH+1, sizeof(unsigned char));
    if(encoded_newData==NULL) return ERR_OUT_OF_MEMORY;
    int result = ckvs_client_crypt_value(mr,1, (const unsigned char*) newValue, strlen(newValue)+1, encoded_newData, outputLength);
    if(result!=ERR_NONE) {
        free(encoded_newData);
        return result;
    }
    if(*outputLength<=0) {
        free(encoded_newData);
        return ERR_IO;
    }
    else {
        *outbuf=encoded_newData;
        return ERR_NONE;
    }
}


/*
 * @param c1 : true if for auth else for c1
 */
int ckvs_client_encrypt_pwd_hmac(ckvs_memrecord_t *mr,bool isAUTH){
    unsigned int size = 0; //variable to remember the size of the HMAC

    unsigned char *hmac = HMAC(EVP_sha256(), mr->stretched_key.sha, SHA256_DIGEST_LENGTH,
                               (const unsigned char*)(isAUTH ? AUTH_MESSAGE : C1_MESSAGE) , strlen((isAUTH ? AUTH_MESSAGE : C1_MESSAGE) ),
                               (isAUTH ? mr->auth_key.sha : mr->c1.sha),&size); //we compute the HMAC of the stretched key with the AUTH_MESSAGE or C1_MESSAGE

    if(hmac == NULL || size != SHA256_DIGEST_LENGTH){
        return ERR_INVALID_COMMAND;
    }
    return ERR_NONE;
}

int ckvs_client_encrypt_pwd(ckvs_memrecord_t *mr, const char *key, const char *pwd)
{
    M_REQUIRE_NON_NULL(mr);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);


    memset(mr, 0, sizeof(*mr));
    char *concat = calloc(strnlen(key,CKVS_MAXKEYLEN)+ strlen(pwd)+2, sizeof(char));
    if(concat==NULL) return ERR_OUT_OF_MEMORY;

    strncat(concat, key,CKVS_MAXKEYLEN);
    strncat(concat, "|", 2);
    strncat(concat,pwd,CKVS_MAXKEYLEN);

    SHA256((unsigned char*) concat, strlen(concat), mr->stretched_key.sha); //we compute the SHA256 and stored it in the stretched key
    free(concat);
    concat=NULL;


    int result = ckvs_client_encrypt_pwd_hmac(mr,true);
    if(result != ERR_NONE) return result;
    result = ckvs_client_encrypt_pwd_hmac(mr,false);
    if(result != ERR_NONE) return result;


    return ERR_NONE;
}



int ckvs_client_compute_masterkey(struct ckvs_memrecord *mr, const struct ckvs_sha *c2) {
    M_REQUIRE_NON_NULL(mr);
    M_REQUIRE_NON_NULL(c2);

    unsigned int size = 0; //variable to remember the size of the HMAC
    unsigned char *hmac = HMAC(EVP_sha256(), mr->c1.sha, SHA256_DIGEST_LENGTH,
                               c2->sha, SHA256_DIGEST_LENGTH,
                               mr->master_key.sha, &size); //we compute the HMAC of the c1 with the c2

    if(hmac == NULL || size != SHA256_DIGEST_LENGTH){
        return ERR_INVALID_COMMAND;
    }

    return ERR_NONE;
}

int ckvs_client_crypt_value(const struct ckvs_memrecord *mr, const int do_encrypt,
                            const unsigned char *inbuf, size_t inbuflen,
                            unsigned char *outbuf, size_t *outbuflen )
{
    /* ======================================
     * Implementation adapted from the web:
     *     https://man.openbsd.org/EVP_EncryptInit.3
     * Man page: EVP_EncryptInit
     * Reference:
     *    https://www.coder.work/article/6383682
     * ======================================
     */

    // constant IV -- ok given the entropy in c2
    unsigned char iv[16];
    bzero(iv, 16);

    // Don't set key or IV right away; we want to check lengths
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL, do_encrypt);

    assert(EVP_CIPHER_CTX_key_length(ctx) == 32);
    assert(EVP_CIPHER_CTX_iv_length(ctx)  == 16);

    // Now we can set key and IV
    const unsigned char* const key = (const unsigned char*) mr->master_key.sha;
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    int outlen = 0;
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, (int) inbuflen)) {
        // Error
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    int tmplen = 0;
    if (!EVP_CipherFinal_ex(ctx, outbuf+outlen, &tmplen)) {
        //ERR_print_errors_fp(stderr);
        // Error
        debug_printf("crypt inbuflen %ld outlen %d tmplen %d", inbuflen, outlen, tmplen);
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);

    *outbuflen = (size_t) outlen;

    return ERR_NONE;
}
