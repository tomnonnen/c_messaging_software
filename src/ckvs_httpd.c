/**
 * @file ckvs_httpd.c
 * @brief webserver
 *
 * @author Edouard Bugnion
 */

#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "error.h"
#include "ckvs_httpd.h"
#include <assert.h>
#include "mongoose.h"
#include <json-c/json.h>
#include <string.h>
#include <curl/curl.h>
#include "util.h"


// Handle interrupts, like Ctrl-C
static int s_signo;

#define BUF_SIZE 1024
#define HTTP_ERROR_CODE 500
#define HTTP_OK_CODE 200
#define HTTP_FOUND_CODE 302
#define HTTP_NOTFOUND_CODE 404

const char* headerHttp = "Content-Type: application/json\r\n";
const char* prefixTmp = "/tmp/";

/**
 * @brief private function that answer the stats call of a client
 *
 * @param nc : connection
 * @param ckvs : the database
 * @param hm : http message
 */
static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs, _unused struct mg_http_message *hm)
{

    //Create Json with the header's data to answer the client
    struct json_object* root = json_object_new_object();

    struct json_object* json_header_string = json_object_new_string(ckvs->header.header_string);
    json_object_object_add(root,"header_string",json_header_string);
    struct json_object* json_version = json_object_new_int((int32_t) ckvs->header.version);
    json_object_object_add(root,"version",json_version);
    struct json_object* json_table_size = json_object_new_int((int32_t) ckvs->header.table_size);
    json_object_object_add(root,"table_size",json_table_size);
    struct json_object* json_threshold_entries = json_object_new_int((int32_t) ckvs->header.threshold_entries);
    json_object_object_add(root,"threshold_entries",json_threshold_entries);
    struct json_object* json_num_entries = json_object_new_int((int32_t) ckvs->header.num_entries);
    json_object_object_add(root,"num_entries",json_num_entries);
    struct json_object* json_keys = json_object_new_array();

    //validCounter is an optimization to avoid looping on all entry to verify if we do not have all entries filled
    for (uint32_t validCounter = 0, readCounter =0 ; validCounter < ckvs->header.num_entries && readCounter<ckvs->header.table_size; readCounter++){
        if(strnlen(ckvs->entries[readCounter].key,CKVS_MAXKEYLEN)!=0) {
            struct json_object* json_key = json_object_new_string(ckvs->entries[readCounter].key);
            json_object_array_add(json_keys,json_key);
            validCounter++;
        }
    }
    json_object_object_add(root,"keys",json_keys);

    //Liberate the Json object
    mg_http_reply(nc, HTTP_OK_CODE, headerHttp, "%s\n", json_object_to_json_string(root));
    json_object_put(root);

}


/**
 * @brief private function that decode an url
 *
 * @param hm : http message
 * @param arg : the key of the url
 * @return a new allocated string or NULL if an error occurred
 */
static char* get_urldecoded_argument(struct mg_http_message *hm, const char *arg)
{
    char buffer[BUF_SIZE]={0};
    int result = mg_http_get_var(&hm->query, arg, buffer, BUF_SIZE);
    if(result <= 0) return NULL;

    CURL *curl = curl_easy_init();
    int outLength =0;
    return curl_easy_unescape(curl,buffer, (int) strnlen(buffer,BUF_SIZE),&outLength);
}


/**
 * @brief Sends an http error message
 *
 * @param nc the http connection
 * @param err the error code corresponding the error message
*/
void mg_error_msg(struct mg_connection* nc, int err)
{
    assert(err>=0 && err < ERR_NB_ERR);
    mg_http_reply(nc, HTTP_ERROR_CODE, NULL, "Error: %s", ERR_MESSAGES[err]);
}

/**
 * @brief Handles signal sent to program, eg. Ctrl+C
 */
static void signal_handler(int signo)
{
    s_signo = signo;
}

/**
 * @brief function that recup the arguments "key" and "auth_key" of the client
 *
 * @param nc : connection
 * @param hm : http message
 * @param key : the key to update
 * @param auth_key : the auth_key to update
 * @return int, an error code
 */
int recup_args(struct mg_connection *nc, _unused struct mg_http_message *hm, char** key, ckvs_sha_t* auth_key){
    char auth_key_string[SHA256_PRINTED_STRLEN]={0};

    *key = get_urldecoded_argument(hm, "key");
    if(*key == NULL){
        curl_free(*key);
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return ERR_INVALID_ARGUMENT;
    }

    int result = mg_http_get_var(&hm->query, "auth_key", auth_key_string, SHA256_PRINTED_STRLEN);
    if(result <=0){
        curl_free(*key);
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return ERR_INVALID_ARGUMENT;
    }

    result = SHA256_from_string(auth_key_string, auth_key);
    if(result <=0){
        curl_free(*key);
        mg_error_msg(nc, ERR_CORRUPT_STORE);
        return ERR_CORRUPT_STORE;
    }

    return ERR_NONE;

}

/**
 * @brief private function that answer the gets call of a client
 * @param nc : the connection
 * @param ckvs : the database
 * @param hm : http message
 */
static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs, _unused struct mg_http_message *hm){

    char* key;
    ckvs_sha_t auth_key;

    //recup the arguments
    int result = recup_args(nc, hm, &key, &auth_key);
    if(result != ERR_NONE) return;

    //find the entry that match the key in the database
    struct ckvs_entry *entry= NULL;
    result = ckvs_find_entry(ckvs,key,&auth_key,&entry);
    curl_free(key);
    if(result!=ERR_NONE) {
        mg_error_msg(nc, result);
        return;
    }

    if(entry->value_len==0){
        mg_error_msg(nc, ERR_NO_VALUE);
        return;
    }

    //create the Json Object
    struct json_object* root = json_object_new_object();

    //first add c2 encoded
    char* buffer = calloc(2*CKVS_MAXKEYLEN+1, sizeof(char));
    SHA256_to_string(&(entry->c2), buffer);
    struct json_object* json_c2 = json_object_new_string(buffer);
    free(buffer);
    json_object_object_add(root, "c2", json_c2);


    //then add data encoded data
    unsigned char* data = calloc(entry->value_len, sizeof(unsigned char));

    fseek(ckvs->file, (long) entry->value_off, SEEK_SET);
    size_t nb_ok = fread(data, entry->value_len, 1, ckvs->file);
    if(nb_ok != 1) {
        free(data);
        return;
    }
    char* buf_data = calloc(2*entry->value_len, sizeof(char));
    hex_encode(data, entry->value_len, buf_data);
    free(data);
    struct json_object* json_data = json_object_new_string(buf_data);
    free(buf_data);
    json_object_object_add(root, "data", json_data);

    //Liberate the Json Object
    mg_http_reply(nc, HTTP_OK_CODE, headerHttp, "%s\n", json_object_to_json_string(root));
    json_object_put(root);


}

/**
 * @brief private function that handle the set call of a client
 *
 * @param nc : the connection
 * @param ckvs : the database
 * @param hm : http message
 */
static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs, _unused struct mg_http_message *hm){
    if(hm->body.len > 0) {
        mg_http_upload(nc, hm, prefixTmp);
    } else {

        ckvs_sha_t auth_key;
        char* key;

        //recup the arguments
        int result = recup_args(nc, hm, &key, &auth_key);
        if(result != ERR_NONE) return;

        //find the entry that match the key in the database
        struct ckvs_entry *entry= NULL;
        result = ckvs_find_entry(ckvs,key,&auth_key,&entry);
        curl_free(key);
        if(result!=ERR_NONE) {
            mg_error_msg(nc, result);
            return;
        }

        //get the name in the url
        char name[SHA256_PRINTED_STRLEN]={0};
        result = mg_http_get_var(&hm->query, "name", name, SHA256_PRINTED_STRLEN);
        if(result <=0){
            mg_error_msg(nc, ERR_OUT_OF_MEMORY);
            return;
        }

        //read the file /tmp/<name>
        char* fileName = calloc(strlen(name)+ strlen(prefixTmp) + 1, sizeof(char)); //we add 1 for the null char
        strncpy(fileName, prefixTmp, strlen(prefixTmp) + 1);
        strncat(fileName, name, strlen(name));

        char* buffer_ptr = NULL;
        size_t buffer_size = 0;
        result = read_value_file_content(fileName, &buffer_ptr, &buffer_size);
        free(fileName);

        //we then extract data and c2
        struct json_object* root = json_tokener_parse(buffer_ptr);

        json_object *json_data;
        if(!json_object_object_get_ex(root, "data", &json_data)){
            mg_error_msg(nc, ERR_IO);
            return;
        }

        json_object *json_c2;
        if(!json_object_object_get_ex(root, "c2", &json_c2)){
            mg_error_msg(nc, ERR_IO);
            return;
        }

        //we decode data
        const char* input = json_object_get_string(json_data);
        unsigned char* secretValue = calloc(strlen(input)/2 + 1, sizeof(char));
        hex_decode(input, secretValue);

        //we decode then c2
        SHA256_from_string(json_object_get_string(json_c2), &(entry->c2));

        //we write the encrypted value of data, with the new value of c2
        result = ckvs_write_encrypted_value(ckvs, entry,  secretValue, strlen(input)/2);
        free(secretValue);
        if(result!=ERR_NONE) {
            mg_error_msg(nc, result);
            return;
        }

        //reply to the client
        mg_http_reply(nc, HTTP_OK_CODE, NULL, NULL);
    }


}





// ======================================================================
/**
 * @brief Handles server events (eg HTTP requests).
 * For more check https://cesanta.com/docs/#event-handler-function
 */
static void ckvs_event_handler(
struct mg_connection *nc, int ev, void *ev_data, void *fn_data)
{
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct CKVS *ckvs = (struct CKVS*) fn_data;

    if (ev != MG_EV_POLL)
        debug_printf("Event received %d", ev);

    switch (ev) {
    case MG_EV_POLL:
    case MG_EV_CLOSE:
    case MG_EV_READ:
    case MG_EV_WRITE:
    case MG_EV_HTTP_CHUNK:
        break;

    case MG_EV_ERROR:
        debug_printf("httpd mongoose error \n");
        break;
    case MG_EV_ACCEPT:
        // students: no need to implement SSL
        assert(ckvs->listening_addr);
        debug_printf("accepting connection at %s\n", ckvs->listening_addr);
        assert (mg_url_is_ssl(ckvs->listening_addr) == 0);
        break;

    case MG_EV_HTTP_MSG:
        if(mg_http_match_uri(hm, "/stats")){
            handle_stats_call(nc,ckvs,hm);
        }
        else if(mg_http_match_uri(hm, "/get")){
            handle_get_call(nc,ckvs,hm);
        }
        else if(mg_http_match_uri(hm, "/set")){
            handle_set_call(nc,ckvs,hm);
        }
        else{
            // handle not implemented call
            mg_error_msg(nc, NOT_IMPLEMENTED);
        }
        break;

    default:
        fprintf(stderr, "ckvs_event_handler %u\n", ev);
        assert(0);
    }
}


// ======================================================================
int ckvs_httpd_mainloop(const char *filename, int optargc, char **optargv)
{
    if (optargc < 1)
        return ERR_NOT_ENOUGH_ARGUMENTS;
    else if (optargc > 1)
        return ERR_TOO_MANY_ARGUMENTS;

    /* Create server */

    signal(SIGINT, signal_handler); //adds interruption signals to the signal handler
    signal(SIGTERM, signal_handler);

    struct CKVS ckvs;
    int err = ckvs_open(filename, &ckvs);

    if (err != ERR_NONE) {
        return err;
    }

    ckvs.listening_addr = optargv[0];

    struct mg_mgr mgr;
    struct mg_connection *c;

    mg_mgr_init(&mgr);

    c = mg_http_listen(&mgr, ckvs.listening_addr, ckvs_event_handler, &ckvs);
    if (c==NULL) {
        debug_printf("Error starting server on address %s\n", ckvs.listening_addr);
        ckvs_close(&ckvs);
        return ERR_IO;
    }

    debug_printf("Starting CKVS server on %s for database %s\n", ckvs.listening_addr, filename);

    while (s_signo == 0) {
        mg_mgr_poll(&mgr, 1000); //infinite loop as long as no termination signal occurs
    }
    mg_mgr_free(&mgr);
    ckvs_close(&ckvs);
    debug_printf("Exiting HTTPD server\n");
    return ERR_NONE;
}
