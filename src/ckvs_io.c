#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "ckvs_crypto.h"
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define PREFIX "CS212 CryptKVS"

static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key);

int generate_newC2(ckvs_sha_t* c2){
    return RAND_bytes(c2->sha,sizeof(ckvs_sha_t));
}



int getValueToSetFromFile(const char* filename, char** buffer_ptr){
    size_t buffer_size = 0;
    int result = read_value_file_content(filename,buffer_ptr,&buffer_size);
    if(result!=ERR_NONE) return result;
    if(buffer_size<=0) return ERR_IO;
    else return ERR_NONE;
}


int ckvs_find_key(struct CKVS *ckvs, const char *key,size_t* index){
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(index);


    size_t i = ckvs_hashkey(ckvs, key);
    uint32_t counter = 0;
    while(counter < ckvs->header.table_size) {
        if (strlen(ckvs->entries[i].key) <= 0) {
            *index = i;
            return ERR_KEY_NOT_FOUND;
        }

        if(!strncmp(key, ckvs->entries[i].key,CKVS_MAXKEYLEN)) {
            *index = i;
            return ERR_NONE;
        } else {
            i++;
            i = i & (ckvs->header.table_size -1);
        }
        counter++;
    }

    return ERR_KEY_NOT_FOUND;

}


int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out){
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);


    size_t i = 0;

    int result = ckvs_find_key(ckvs,key,&i);

    if(result != ERR_NONE) return result;
    else{
        if(!ckvs_cmp_sha(auth_key, &ckvs->entries[i].auth_key)){
            *e_out = &(ckvs->entries[i]);
            return ERR_NONE;
        } else{
            return ERR_DUPLICATE_ID;
        }
    }

}

/*
* @param number verif if power of two
* @return bool, 1 if power of two else 0
*/
int is_power_of_two(size_t number){
    if(number==1) return 1;
    else if(number ==0 || number %2) return 0;
    else return is_power_of_two(number/2);
}

/**
 * @brief Opens the CKVS database at filename.
 * Also checks that the database is valid, as described in 04.stats.md
 *
 * @param filename (const char*) the path to the database to open
 * @param ckvs (struct CKVS*) the struct that will be initialized
 * @return int, error code
 */
int ckvs_open(const char *filename, struct CKVS *ckvs){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(ckvs);
    memset(ckvs, 0, sizeof(*ckvs));
    ckvs->file = fopen(filename, "r+b");
    if(ckvs->file == NULL) return ERR_IO;


    //reading the headers
    memset(&ckvs->header, 0, sizeof(ckvs->header));
    size_t nb_ok = fread(&ckvs->header, sizeof(struct ckvs_header), 1, ckvs->file);//we read the headers of the file
    if (nb_ok != 1) {
        fclose(ckvs->file);
        ckvs->file = NULL;
        return ERR_IO;
    }

    //checking there is no errors
    if(strncmp(PREFIX, ckvs->header.header_string, strlen(PREFIX)) != 0
       || ckvs->header.version != 1
       || is_power_of_two(ckvs->header.table_size)==0){
        fclose(ckvs->file);
        ckvs->file = NULL;
        return ERR_CORRUPT_STORE;
    }


    //====================
    //reading the entries
    ckvs->entries = calloc(ckvs->header.table_size,sizeof(struct ckvs_entry));
    if(ckvs->entries == NULL) return ERR_OUT_OF_MEMORY;
    nb_ok = fread(ckvs->entries, sizeof(struct ckvs_entry), ckvs->header.table_size, ckvs->file);//we read the entries of the file
    //checking there is no errors
    if (nb_ok != ckvs->header.table_size) {
        if(ckvs->entries != NULL) {
            free(ckvs->entries);
            ckvs->entries = NULL;
        }
        fclose(ckvs->file);
        ckvs->file = NULL;
        return ERR_IO;
    }
    return ERR_NONE;

}



void ckvs_close(struct CKVS *ckvs){
    if(ckvs==NULL || ckvs->file==NULL) return;
    if(ckvs->entries != NULL) {
        free(ckvs->entries);
        ckvs->entries = NULL;
    }
    fclose(ckvs->file);
    ckvs->file = NULL;
}




int read_value_file_content(const char* filename, char** buffer_ptr, size_t* buffer_size){

    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(buffer_ptr);
    M_REQUIRE_NON_NULL(buffer_size);

    FILE* file = fopen(filename, "rb");
    if(file == NULL) return ERR_IO;

    //getting the length of the file
    int result = fseek(file,0,SEEK_END);
    if(result !=0){
        fclose(file); //we close the file
        return ERR_IO;
    }
    size_t fileSize = (size_t) ftell(file);//get the size by subtracting the start of the file to the end
    rewind(file);//sets the file position to the beginning of the file

    //creating buffer

    char* contentPointeur = calloc(fileSize+1,sizeof(char));//we initialize the buffer contentPointeur
    if(contentPointeur==NULL) return ERR_OUT_OF_MEMORY;
    size_t readSize = fread(contentPointeur, sizeof(char), fileSize,file);//read the file
    if(readSize != fileSize) {
        //free(contentPointeur); TODO
        fclose(file); //we close the file
        return ERR_IO;
    }
    contentPointeur[fileSize] = '\0';

    *buffer_ptr = contentPointeur;
    *buffer_size = fileSize;
    fclose(file);//we close the file
    return ERR_NONE;
}



static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx){
    M_REQUIRE_NON_NULL(ckvs);

    size_t entryPosition = sizeof(ckvs_header_t)+idx*sizeof(ckvs_entry_t);

    int result  = fseek(ckvs->file, (long) entryPosition, SEEK_SET);
    if(result!= 0) return ERR_IO;
    size_t writedLength = fwrite(&ckvs->entries[idx],sizeof(struct ckvs_entry),1,ckvs->file);
    if(writedLength!= 1) return ERR_IO;

    return ERR_NONE;
}





int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e, const unsigned char *buf, uint64_t buflen){
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(e);
    M_REQUIRE_NON_NULL(buf);


    int result  = fseek(ckvs->file,0, SEEK_END);
    if(result!= 0) return ERR_IO;

    long entryIndex = e - ckvs->entries;
    e->value_off = (uint64_t) ftell(ckvs->file);
    e->value_len = buflen;

    size_t writeResult = fwrite(buf,buflen,1,ckvs->file);
    if(writeResult != 1) return ERR_IO;

    result = ckvs_write_entry_to_disk(ckvs,(uint32_t) entryIndex); //loss of precision with risk of overflow from the cast
    if(result!= ERR_NONE) return result;

    return ERR_NONE;
}

int ckvs_new_entry(struct CKVS *ckvs, const char *key, struct ckvs_sha *auth_key, struct ckvs_entry **e_out){
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);


    //verif we haven't already reach the max number of entries
    if(ckvs->header.num_entries >=ckvs->header.threshold_entries) return ERR_MAX_FILES;


    //uint32_t entryIndex = newEntry - ckvs->entries;
    size_t entryIndex =0;
    int result = ckvs_find_key(ckvs,key,&entryIndex);
    if(result==ERR_NONE) return ERR_DUPLICATE_ID; //vérif that the key doesn't already exist
    else if(result!=ERR_KEY_NOT_FOUND) return result;
    memset(&ckvs->entries[entryIndex], 0, sizeof(ckvs->entries[entryIndex])); //initilize all field to 0
    strncpy(ckvs->entries[entryIndex].key ,key,CKVS_MAXKEYLEN); //key is copied
    ckvs->entries[entryIndex].auth_key = *auth_key;


    result = ckvs_write_entry_to_disk(ckvs,(uint32_t)entryIndex);
    if(result!= ERR_NONE) return result;

    //update header for taking new elem into account
    ckvs->header.num_entries++;
    const long headerPosition = 0;
    fseek(ckvs->file,headerPosition,SEEK_SET);
    size_t writedLength = fwrite(&ckvs->header,sizeof(struct ckvs_header),1,ckvs->file);
    if(writedLength!= 1) return ERR_IO;


    *e_out =  &ckvs->entries[entryIndex];


    return ERR_NONE;



}

static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key)
{
    M_REQUIRE_NON_NULL(ckvs);

    const size_t nr_bytes = 4;

    unsigned char buf[SHA256_DIGEST_LENGTH] = {0};
    SHA256((const unsigned char*) key, strlen(key), buf); //we compute the SHA256 and stored it in the buffer
    uint32_t res;
    memcpy(&res, buf, nr_bytes); // we copy the bytes of the buffer to the var res

    uint32_t lsb = res & (ckvs->header.table_size - 1);
    return lsb;

}

