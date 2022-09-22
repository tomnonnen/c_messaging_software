#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include "ckvs_utils.h"
#include "ckvs.h"
#include "ckvs_rpc.h"
#include "json-c/json_object.h"
#include "json-c/json_tokener.h"
#include "ckvs_crypto.h"
#include "ckvs_io.h"
#include "util.h"

const char* prefixForGetParam = "/get?";
const char* prefixForSetParam = "/set?";
const char* prefixForStatsParam = "/stats";
const char* prefixKey = "key=";
const char* prefixAuth = "&auth_key=";
const char* mg_upload_prefixName = "&name=";
const char* mg_upload_Name = "data.json";
const char* mg_upload_prefixOffset = "&offset=";
const char* mg_upload_Offset = "0";
const char* err_key_pwd_json = "Incorrect key/password or Key not found or json incorrect";

/**
 * @brief private function that get an int given a json object
 *
 * @param root (struct json_object*) the json to analyze
 * @param number (uint32_t*) the int to write
 * @param keyName (const char*) the name of the key for the json object
 * @return int, an error code
 */
int client_get_int(struct json_object *root,uint32_t *number,const char *keyName){
    json_object *tmp;
    if (json_object_object_get_ex(root, keyName, &tmp)){    //if the key exist
        *number = (uint32_t) json_object_get_int(tmp);
    }
    else {
        return ERR_IO;
    }
    return ERR_NONE;
}

/**
 * @brief private function that get a string given a json object
 *
 * @param root (struct json_object*) the json to analyze
 * @param string (char*) the string to write
 * @param keyName (const char*) the name of the key for the json object
 * @param len (size_t) the len of the string
 * @return int, an error code
 */
int client_get_string(struct json_object *root,char *string,const char *keyName, size_t len){
    json_object *tmp;
    if (json_object_object_get_ex(root, keyName, &tmp)){    //if the key exist
        strncpy(string,json_object_get_string(tmp),len);
    }
    else {
        return ERR_IO;
    }
    return ERR_NONE;
}

/**
 * @brief private function that decode and then decrypt data (used only in analyze_json)
 *
 * @param ckvs_connection : the connection
 * @param mr : ckvs_memrecord that contains the crypto data
 * @param readValue : the read value of
 * @param decoded : contains the decoded data of the json
 * @param data : contains the data of the json
 * @param dataSize : the size of the data
 * @return int, an error code
 */
int decode_decrypt_data(ckvs_connection_t* ckvs_connection, const struct ckvs_memrecord *mr, uint8_t* readValue, unsigned char* decoded,const char* data, size_t dataSize){

    if(readValue == NULL || decoded == NULL){
        ckvs_rpc_close(ckvs_connection);
        return ERR_OUT_OF_MEMORY;
    }

    hex_decode(data,readValue);
    size_t outLength =0;
    int result = ckvs_client_crypt_value(mr, 0,  readValue, dataSize,(unsigned char*)decoded,&outLength);
    M_REQUIRE_ERR_NONE(result, *ckvs_connection);
    free(readValue);
    
    return ERR_NONE;
}

/**
 *
 * @brief private function that analyze the root json (used only in ckvs_client_get)
 *
 * @param ckvs_connection : the connection
 * @param root : the json we get and we analyze
 * @param mr : ckvs_memrecord that contains the crypto data
 * @return int, an error code
 */
int analyze_json(ckvs_connection_t* ckvs_connection, struct json_object *root, ckvs_memrecord_t* mr){
    //1) Get and decode c2
    ckvs_sha_t c2;
    json_object *json_c2;
    if(!json_object_object_get_ex(root, "c2", &json_c2)){
        pps_printf("%s", err_key_pwd_json);
        ckvs_rpc_close(ckvs_connection);
        return ERR_IO;
    }
    const char* encoded_c2 = json_object_get_string(json_c2);

    SHA256_from_string(encoded_c2, &c2);

    //2) Compute the Master key
    int result = ckvs_client_compute_masterkey(mr, &c2);
    if(result!=ERR_NONE){
        ckvs_rpc_close(ckvs_connection);
        json_object_put(root);
        return result;
    }

    //3) Get, decode, and decrypt data
    json_object *json_data;
    if(!json_object_object_get_ex(root, "data", &json_data)){
        pps_printf("%s", err_key_pwd_json);
        ckvs_rpc_close(ckvs_connection);
        return ERR_IO;
    }

    const char* data = json_object_get_string(json_data);
    size_t dataSize = strlen(data)/2 + (strlen(data)%2 !=0);

    uint8_t* readValue = calloc(dataSize, sizeof(uint8_t));
    unsigned char* decoded = calloc(dataSize+EVP_MAX_BLOCK_LENGTH, sizeof(unsigned char));

    result = decode_decrypt_data(ckvs_connection, mr, readValue, decoded, data, dataSize);
    if(result != ERR_NONE){
        free(decoded);
        return result;
    }

    //Close the connection and print the decypted and decoded value of data
    ckvs_rpc_close(ckvs_connection);
    pps_printf("%s",decoded);
    free(decoded);

    return ERR_NONE;

}

/**
 *
 * @brief private function that prepare the url to get (used only in ckvs_client_get)
 *
 * @param ckvs_connection : the connection
 * @param keyEscaped : the escaped key
 * @param urlRoot : the root of the url
 * @param tmp : buffer to decodes the data
 * @param mr : ckvs_memrecord that contains the crypto data
 * @return int, an error code
 */
int prepare_url(ckvs_connection_t* ckvs_connection, char* keyEscaped, char* urlRoot, char* tmp, ckvs_memrecord_t* mr){

    if(keyEscaped == NULL || urlRoot == NULL || tmp == NULL){
        ckvs_rpc_close(ckvs_connection);
        return ERR_OUT_OF_MEMORY;
    }

    //1)Initialization
    strncpy(urlRoot, prefixForGetParam, strlen(prefixForGetParam)); //we first initialize urlRoot wih the prefix for get

    //2)Concatenation
    strncat(urlRoot, prefixKey, strlen(prefixKey)); //we then concatenate with the prefix for the key
    strncat(urlRoot, keyEscaped, strlen(keyEscaped)); //we then concatenate with the escaped key
    curl_free(keyEscaped);
    strncat(urlRoot, prefixAuth, strlen(prefixAuth)); //at the end we concatenate with the prefix for auth key


    //3)Concatenate the encoded auth_key
    SHA256_to_string(&mr->auth_key,tmp);
    strncat(urlRoot, tmp, 2*SHA256_DIGEST_LENGTH);
    free(tmp);

    return ERR_NONE;

}


int ckvs_client_stats(const char *url, int optargc, ossl_unused char **optargv){

    //Verification of the args
    if(optargc < 0) return ERR_NOT_ENOUGH_ARGUMENTS;
    if(optargc > 0) return ERR_TOO_MANY_ARGUMENTS;

    M_REQUIRE_NON_NULL(url);

    //Initialization of the connection
    ckvs_connection_t ckvs_connection;
    int result = ckvs_rpc_init(&ckvs_connection, url);
    if(result != ERR_NONE) return result;
    result = ckvs_rpc(&ckvs_connection, prefixForStatsParam);
    M_REQUIRE_ERR_NONE(result, ckvs_connection);

    //Get the json from the connection
    struct json_object *root = json_tokener_parse(ckvs_connection.resp_buf); //create the structure

    enum json_tokener_error jerr = json_tokener_get_error((struct json_tokener *) root);
    if(jerr != json_tokener_success){
        pps_printf("%s", json_tokener_error_desc(jerr));
        ckvs_rpc_close(&ckvs_connection);
        return ERR_IO;
    }

    //Analyse the json to print the ckvs_header
    ckvs_header_t ckvs_header;

    result = client_get_string(root,ckvs_header.header_string,"header_string",CKVS_HEADERSTRINGLEN);
    M_REQUIRE_ERR_NONE(result, ckvs_connection);

    result= client_get_int(root,&ckvs_header.version,"version");
    M_REQUIRE_ERR_NONE(result, ckvs_connection);

    result= client_get_int(root,&ckvs_header.table_size,"table_size");
    M_REQUIRE_ERR_NONE(result, ckvs_connection);

    result= client_get_int(root,&ckvs_header.threshold_entries,"threshold_entries");
    M_REQUIRE_ERR_NONE(result, ckvs_connection);

    result= client_get_int(root,&ckvs_header.num_entries,"num_entries");
    M_REQUIRE_ERR_NONE(result, ckvs_connection);

    print_header(&ckvs_header);

    //Analyse the json to print the keys
    struct json_object *keys;
    if(!json_object_object_get_ex(root, "keys", &keys)){
        ckvs_rpc_close(&ckvs_connection);
        return ERR_IO;
    }

    for(size_t i=0; i<ckvs_header.num_entries; i++) {
        struct json_object* key = json_object_array_get_idx(keys, i);
        pps_printf("%-9s : "STR_LENGTH_FMT(CKVS_MAXKEYLEN)"\n", "Key", json_object_get_string(key));
    }

    //Close the connection and return ERR_NONE
    ckvs_rpc_close(&ckvs_connection);

    return ERR_NONE;
}


int ckvs_client_get(const char *url, int optargc, char **optargv) {

    //Verification of the args
    if(optargc < 2) return ERR_NOT_ENOUGH_ARGUMENTS;
    if(optargc > 2) return ERR_TOO_MANY_ARGUMENTS;

    M_REQUIRE_NON_NULL(url);
    M_REQUIRE_NON_NULL(optargv);

    const char* key = optargv[0];
    const char* pwd = optargv[1];
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);

    //Initialization of the connection
    ckvs_connection_t ckvs_connection;
    int result = ckvs_rpc_init(&ckvs_connection, url);
    if(result != ERR_NONE){
        return result;
    }

    //Generates stretched_key, auth_key and c1 and stores them into the memrecord mr
    ckvs_memrecord_t mr;
    result = ckvs_client_encrypt_pwd(&mr,key,pwd);
    M_REQUIRE_ERR_NONE(result, ckvs_connection);

    //Preparation of the URL to get
    char* keyEscaped = curl_easy_escape(ckvs_connection.curl, key, (int) strlen(key));
    char* urlRoot = calloc(strlen(prefixForGetParam)+strlen(prefixKey) + strlen(keyEscaped)+ strlen(prefixAuth) + 2*SHA256_PRINTED_STRLEN+1, sizeof(char));
    char* tmp = calloc(2*SHA256_DIGEST_LENGTH+1, sizeof(char));
    result = prepare_url(&ckvs_connection, keyEscaped, urlRoot, tmp, &mr);
    if(result != ERR_NONE) return result;

    //Get the URL
    result = ckvs_rpc(&ckvs_connection, urlRoot);
    free(urlRoot);
    M_REQUIRE_ERR_NONE(result, ckvs_connection);

    //Get the json from the connection
    struct json_object *root = json_tokener_parse(ckvs_connection.resp_buf); //create the structure
    if(root==NULL){
        pps_printf("%s\n",ckvs_connection.resp_buf);
        ckvs_rpc_close(&ckvs_connection);
        return ERR_IO;
    }

    //Analyze the Json
    result = analyze_json(&ckvs_connection, root, &mr);
    if(result != ERR_NONE) return result;

    return ERR_NONE;

}



/*
 * 1. Générer `auth_key`, `c2` et `master_key`, de la même manière que pour un `set` en local;
2. Lire le fichier contenant le secret à envoyer et le chiffrer;
3. Initialiser la connection au serveur;
4. Préparer l'url de la requête, qui doit contenir les arguments `key` (url-escaped), `auth_key` (hex-encodée) ainsi que `name` et `offset` comme décrit ci-dessus;
5. Préparer le corps du POST: un string au format json qui contient la nouvelle valeur de `c2` (hex-encodée) et la valeur encryptée `data` (hex-encodée également);
6. Appeler `ckvs_post` avec les arguments ainsi préparés;
7. Appeler `ckvs_post` une seconde fois avec un payload vide, pour signaler la fin du transfert au serveur.
 */
int ckvs_client_set(const char *url, int optargc, char **optargv) {
    if(optargc < 3) return ERR_NOT_ENOUGH_ARGUMENTS;
    if(optargc > 3) return ERR_TOO_MANY_ARGUMENTS;

    M_REQUIRE_NON_NULL(url);

    //init des structures
    const char* key = optargv[0];
    const char* pwd = optargv[1];
    const char* filename = optargv[2];
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);
    M_REQUIRE_NON_NULL(filename);

    //1.a generate new auth_key

    ckvs_memrecord_t mr;
    int result = generateAuthKeyStrechedKeyC1(&mr,key,pwd);
    if(result!=ERR_NONE) {
        return result;
    }
    //1.a generate new auth_key end - - - - - - - - - - - - - - - - - - - - - - - -
    //1.b generate new C2  - - - - - - - - - - - - - - - - - - - - - - - -
    struct ckvs_sha newC2;
    result = generate_newC2(&newC2);
    //1.b  generate new C2 end - - - - - - - - - - - - - - - - - - - - - - - -

    //1.c generate masterKey  - - - - - - - - - - - - - - - - - - - - - - - -

    result = generateMasterKey(&mr, &newC2);
    if(result!=ERR_NONE){
        return result;
    }
    //1.c generate masterKey  end - - - - - - - - - - - - - - - - - - - - - - - -

    //2.a read filecontent
    char* set_value = NULL;
    result = getValueToSetFromFile(filename,&set_value);
    if(result!=ERR_NONE) return result;
    //read fileContent end - - - - - - - - - - - - - - - - - - - - - - - -


    //2.b chiffre fileContent  (crypter le contenu <filename>) - - - - - - - - - - - - - - - - - - - - - - - -
    unsigned char* encoded_newData = NULL;
    size_t encoded_newData_outLength = 0;
    result = encodeNewValue(&mr,set_value,&encoded_newData,&encoded_newData_outLength);
    if(result!=ERR_NONE) {//encoded_newData is not allocated
        return result;
    }
    //chiffre fileContent end - - - - - - - - - - - - - - - - - - - - - - - -


    //3 Initializate server connection - - - - - - - - - - - - - - - - - - - - - - - -
    ckvs_connection_t ckvs_connection;
    memset(&ckvs_connection, 0, sizeof(ckvs_connection_t));
    result = ckvs_rpc_init(&ckvs_connection, url);
    if(result != ERR_NONE){
        return result;
    }
    //3 Initializate server connection end - - - - - - - - - - - - - - - - - - - - - - - -

    //4. prepare url - - - - - - - - - - - - - - - - - - - - - - - -

    //url escaped key
    char* keyEscaped = curl_easy_escape(ckvs_connection.curl, key, (int) strlen(key));
    if(keyEscaped == NULL){
        ckvs_rpc_close(&ckvs_connection);
        return ERR_OUT_OF_MEMORY;
    }

    char* urlGetParam = calloc(strlen(prefixForSetParam)+strlen(prefixKey) + strlen(keyEscaped)+ strlen(prefixAuth) + 2*SHA256_PRINTED_STRLEN +strlen(mg_upload_prefixName)+strlen(mg_upload_Name)+strlen(mg_upload_prefixOffset)+strlen(mg_upload_Offset)+1, sizeof(char));

    strncpy(urlGetParam, prefixForSetParam, strlen(prefixForSetParam));

    //add prefix for parameter key
    strncat(urlGetParam, prefixKey, strlen(prefixKey));


    //add key to url
    strncat(urlGetParam, keyEscaped, strlen(keyEscaped));
    curl_free(keyEscaped);

    //add prefix for parameter auth_key
    strncat(urlGetParam, prefixAuth, strlen(prefixAuth));

    //hex encode auth_key + add to url
    char* tmp = calloc(2*SHA256_DIGEST_LENGTH+1, sizeof(char));
    SHA256_to_string(&mr.auth_key,tmp);
    strncat(urlGetParam, tmp, 2*SHA256_DIGEST_LENGTH);
    free(tmp);


    //add arg necessary for mg_http_upload to the url
    strncat(urlGetParam, mg_upload_prefixName, strlen(mg_upload_prefixName));
    strncat(urlGetParam, mg_upload_Name, strlen(mg_upload_Name));
    strncat(urlGetParam, mg_upload_prefixOffset, strlen(mg_upload_prefixOffset));
    strncat(urlGetParam, mg_upload_Offset, strlen(mg_upload_Offset));

    //4. prepare url end - - - - - - - - - - - - - - - - - - - - - - - -


    struct json_object* root = json_object_new_object();

    //hex_encode the new C2 value + add it to the json root
    char* hex_encoded_newC2 = calloc(2*SHA256_DIGEST_LENGTH+1, sizeof(char));
    SHA256_to_string(&newC2,hex_encoded_newC2);
    struct json_object* json_newC2_string = json_object_new_string(hex_encoded_newC2);
    free(hex_encoded_newC2);
    json_object_object_add(root,"c2",json_newC2_string);

    //hex_encode the new data + add it to the json root
    char* hex_encoded_newData = calloc(2*encoded_newData_outLength+1, sizeof(char));
    hex_encode(encoded_newData, encoded_newData_outLength, hex_encoded_newData);
    struct json_object* json_encryptedData_string = json_object_new_string(hex_encoded_newData);
    json_object_object_add(root,"data",json_encryptedData_string);

    ckvs_post(&ckvs_connection,urlGetParam,json_object_to_json_string(root));
    free(hex_encoded_newData);
    json_object_put(root); //liberate le json object
    free(set_value);
    return result;//if no error => no error in the whole function
}

int ckvs_client_new(ossl_unused const char *url, ossl_unused int optargc,ossl_unused char **optargv){
    return NOT_IMPLEMENTED;
}