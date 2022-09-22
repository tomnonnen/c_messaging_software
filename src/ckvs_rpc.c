/**
 * @file ckvs_rpc.c
 * @brief RPC handling using libcurl
 * @author E. Bugnion
 *
 * Includes example from https://curl.se/libcurl/c/getinmemory.html
 */
#include <stdlib.h>

#include "ckvs_rpc.h"
#include "error.h"
#include "ckvs_utils.h"

/**
 * ckvs_curl_WriteMemoryCallback -- lifted from https://curl.se/libcurl/c/getinmemory.html
 *
 * @brief Callback that gets called when CURL receives a message.
 * It writes the payload inside ckvs_connection.resp_buf.
 * Note that it is already setup in ckvs_rpc_init.
 *
 * @param contents (void*) content received by CURL
 * @param size (size_t) size of an element of of content. Always 1
 * @param nmemb (size_t) number of elements in content
 * @param userp (void*) points to a ckvs_connection (set with the CURLOPT_WRITEDATA option)
 * @return (size_t) the number of written bytes, or 0 if an error occured
 */
static size_t ckvs_curl_WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct ckvs_connection *conn = (struct ckvs_connection *)userp;

    char *ptr = realloc(conn->resp_buf, conn->resp_size + realsize + 1);
    if(!ptr) {
        /* out of memory! */
        debug_printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    conn->resp_buf = ptr;
    memcpy(&(conn->resp_buf[conn->resp_size]), contents, realsize);
    conn->resp_size += realsize;
    conn->resp_buf[conn->resp_size] = 0;

    return realsize;
}


int ckvs_rpc_init(struct ckvs_connection *conn, const char *url)
{
    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(url);
    bzero(conn, sizeof(*conn));

    conn->url  = url;
    conn->curl = curl_easy_init();
    if (conn->curl == NULL) {
        return ERR_OUT_OF_MEMORY;
    }
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, ckvs_curl_WriteMemoryCallback);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, (void *)conn);

    return ERR_NONE;
}

void ckvs_rpc_close(struct ckvs_connection *conn)
{
    if (conn == NULL)
        return;

    if (conn->curl) {
        curl_easy_cleanup(conn->curl);
    }
    if (conn->resp_buf) {
        free(conn->resp_buf);
    }
    bzero(conn, sizeof(*conn));
}
int setCurlUrlGET(char* baseUrl, struct ckvs_connection *conn, const char *GET){
    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(GET);

    strcpy(baseUrl, conn->url);
    strcat(baseUrl, GET);
    CURLcode ret = curl_easy_setopt(conn->curl, CURLOPT_URL, baseUrl);
    if(ret != CURLE_OK) return ERR_IO;

    return ERR_NONE;
}

int ckvs_rpc(struct ckvs_connection *conn, const char *GET)
{

    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(GET);

    char* url = calloc(strlen(conn->url)+strlen(GET)+1,sizeof(char*));
    if(url == NULL) return ERR_OUT_OF_MEMORY;
    int result = setCurlUrlGET(url,conn,GET);
    if(result!=ERR_NONE) return result;
    CURLcode ret = curl_easy_perform(conn->curl);
    free(url);
    if(ret != CURLE_OK){
        return ERR_TIMEOUT;
    }

    return ERR_NONE;
}


int ckvs_post(struct ckvs_connection* conn, const char* GET, const char* POST)
{
    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(GET);
    M_REQUIRE_NON_NULL(POST);

    char* url = calloc(strlen(conn->url)+strlen(GET),sizeof(char*));
    if(url == NULL) return ERR_OUT_OF_MEMORY;
    int result = setCurlUrlGET(url,conn,GET);
    if(result!=ERR_NONE) return result;

    CURLcode ret = curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDS, POST);
    if(ret != CURLE_OK) return ERR_IO;
    ret = curl_easy_perform(conn->curl);
    if(ret != CURLE_OK){
        return ERR_TIMEOUT;
    }

    //signal end to server by sending empty post string
    ret = curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDS, "");
    if(ret != CURLE_OK) return ERR_IO;
    ret = curl_easy_perform(conn->curl);
    if(ret != CURLE_OK){
        return ERR_TIMEOUT;
    }
    if(conn->resp_buf!=NULL && strlen(conn->resp_buf)>0){
        pps_printf("%s",conn->resp_buf);
        return ERR_IO;
    }

    free(url);
    return ERR_NONE;
}



