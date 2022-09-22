#include <stdio.h>
#include <string.h>
#include "ckvs_utils.h"
#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "util.h"

#define MAXIMALSECRETSIZE 1200

/**
 * @brief private function that combine the tasks of the ckvs_local_get and ckvs_local_set functions
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param key (const char*) the key of the entry to set
 * @param pwd (const char*) the password of the entry to set
 * @param set_value (const char*) the path to the file which contains what will become the new encrypted content of the entry or NULL for the get function
 * @return int, an error code
 */
int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char* set_value);

int ckvs_local_stats(const char *filename, _unused int optargc, _unused char *optargv[]){
    if(optargc < 0) return ERR_NOT_ENOUGH_ARGUMENTS;
    if(optargc > 0) return ERR_TOO_MANY_ARGUMENTS;
    struct CKVS ckvs;
    memset(&ckvs, 0, sizeof(ckvs));
    int result = ckvs_open(filename,&ckvs);
    if(result!=ERR_NONE) return result;

    print_header(&ckvs.header);

    //read and print the entries of the database ckvs
    //validCounter is an optimization to avoid looping on all entry to verify if we do not have all entries filled
    for (uint32_t validCounter = 0, readCounter =0 ; validCounter < ckvs.header.num_entries && readCounter<ckvs.header.table_size; readCounter++){
        if(strnlen(ckvs.entries[readCounter].key,CKVS_MAXKEYLEN)!=0) {
            print_entry(&ckvs.entries[readCounter]);
            validCounter++;
        }
    }

    ckvs_close(&ckvs);
    return ERR_NONE;
}



int ckvs_local_get(const char* filename, int optargc, char* optargv[]){
    if(optargc < 2) return ERR_NOT_ENOUGH_ARGUMENTS;
    if(optargc > 2) return ERR_TOO_MANY_ARGUMENTS;

    int result = ckvs_local_getset(filename,optargv[0], optargv[1],NULL);
    if(result!=ERR_NONE) return result;
    return ERR_NONE;

}

int ckvs_local_set(const char* filename, int optargc, char* optargv[]){
    //0 : key, 1 : pwd, 2 : filename
    if(optargc < 3) return ERR_NOT_ENOUGH_ARGUMENTS;
    if(optargc > 3) return ERR_TOO_MANY_ARGUMENTS;


    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(optargv[0]);
    M_REQUIRE_NON_NULL(optargv[1]);
    M_REQUIRE_NON_NULL(optargv[2]);


    const char* key = optargv[0];
    const char* pwd = optargv[1];
    const char* filenameNameValuetoSet = optargv[2];

    char* set_value = NULL;

    int result = getValueToSetFromFile(filenameNameValuetoSet,&set_value);
    if(result!=ERR_NONE) return result;

    result = ckvs_local_getset(filename,key,pwd,set_value);
    free(set_value);

    return result;//if no error => no error in the whole function

}

int do_get(struct CKVS ckvs,ckvs_memrecord_t mr,struct ckvs_entry *entry){
    unsigned char* readValue = calloc(entry->value_len, sizeof(unsigned char));

    if(entry->value_len==0) return ERR_NO_VALUE;
    fseek(ckvs.file, (long) entry->value_off, SEEK_SET);
    size_t nb_ok = fread(readValue, entry->value_len, 1, ckvs.file);
    if(nb_ok != 1) {
        free(readValue);
        return ERR_IO;
    }

    int result = ckvs_client_compute_masterkey(&mr, &entry->c2);
    if(result!=ERR_NONE) {
        free(readValue);
        return result;
    }

    unsigned char* decoded = calloc(entry->value_len+EVP_MAX_BLOCK_LENGTH, sizeof(unsigned char));
    size_t outLength =0;
    result = ckvs_client_crypt_value(&mr,0,(const unsigned char*) readValue, entry->value_len,(unsigned char*)decoded,&outLength);
    free(readValue);
    if(result!=ERR_NONE) {
        free(decoded);
        return result;
    }
    pps_printf("%s",decoded);
    free(decoded);
    return ERR_NONE;
}


int do_set(struct CKVS ckvs,ckvs_memrecord_t mr,struct ckvs_entry *entry,const char* set_value){


    //int result = ckvs_client_compute_masterkey(&mr, &entry->c2);
    int result = generateMasterKey(&mr, &entry->c2);
    if(result!=ERR_NONE){
        return result;
    }


    //crypter le contenu <filename>
    unsigned char* encoded_newData = NULL;
    size_t encoded_newData_outLength = 0;
    result = encodeNewValue(&mr,set_value,&encoded_newData,&encoded_newData_outLength);
    if(result!=ERR_NONE) {
        return result;
    }

    //stocker dans database
    result = ckvs_write_encrypted_value(&ckvs, entry,encoded_newData, encoded_newData_outLength);
    if(result!=ERR_NONE) {
        free(encoded_newData);
        return result;
    }

    free(encoded_newData);
    return ERR_NONE;
}

int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char* set_value){

    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);

    //ouvrir la base de donnee
    struct CKVS ckvs;
    int result = ckvs_open(filename,&ckvs);
    if(result!=ERR_NONE) return result;

    //s'assurer que la clef existe et que le mot de passe correspond
    ckvs_memrecord_t mr;
    result = generateAuthKeyStrechedKeyC1(&mr,key,pwd);
    if(result!=ERR_NONE) {
        ckvs_close(&ckvs);
        return result;
    }

    struct ckvs_entry *entry= NULL;
    result = ckvs_find_entry(&ckvs,key,&mr.auth_key,&entry);
    if(result!=ERR_NONE) {
        ckvs_close(&ckvs);
        return result;
    }

    if(set_value !=NULL){
        result = generate_newC2(&entry->c2);
        if(result!=1){
            ckvs_close(&ckvs);
            return result;
        }

    }

    result = set_value==NULL ? do_get(ckvs, mr, entry) : do_set(ckvs, mr, entry, set_value);
    if(result != ERR_NONE){
        ckvs_close(&ckvs);
        return result;
    }


    ckvs_close(&ckvs);

    return ERR_NONE;

}


int ckvs_local_new(const char* filename, int optargc, char* optargv[]){
    if(optargc < 2) return ERR_NOT_ENOUGH_ARGUMENTS;
    if(optargc > 2) return ERR_TOO_MANY_ARGUMENTS;
    //0 : key 1: pwd
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(optargv[0]);
    M_REQUIRE_NON_NULL(optargv[1]);

    if(strlen(optargv[0])>CKVS_MAXKEYLEN) return ERR_INVALID_ARGUMENT; //verify that the key isn't too big

    //ouvrir la base de donnee
    struct CKVS ckvs;


    int result = ckvs_open(filename,&ckvs);

    if(result!=ERR_NONE) return result;



    //creer et generer l'auth key
    ckvs_memrecord_t mr;
    memset(&mr, 0, sizeof(mr)); //on le fait deja dans la func
    result = ckvs_client_encrypt_pwd(&mr,optargv[0],optargv[1]);

    if(result!=ERR_NONE) {
        ckvs_close(&ckvs);
        return result;
    }



    struct ckvs_entry *entry= NULL;
    result = ckvs_new_entry(&ckvs, optargv[0], &(mr.auth_key), &entry);
    if(result!=ERR_NONE) {
        ckvs_close(&ckvs);
        return result;
    }







    ckvs_close(&ckvs);

    return ERR_NONE;

}
