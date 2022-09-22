//
// Created by theo on 16.03.22.
//
#include "ckvs_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <values.h>
#include "ckvs.h"
#include "util.h"



void hex_encode(const uint8_t *in, size_t len, char *buf){
    if(in==NULL || buf==NULL) return;

    for (size_t i = 0; i < len; ++i) {
        sprintf(&buf[i*2], "%02x", in[i]);
    }
}

void SHA256_to_string(const struct ckvs_sha *sha, char *buf){
    if(sha ==NULL || buf==NULL)return;

    hex_encode(sha->sha, SHA256_DIGEST_LENGTH, buf);
}


void print_header(const struct ckvs_header* header){
    if(header ==NULL) return;

    pps_printf("CKVS Header type       : %s\n"
               "CKVS Header version    : %d\n"
               "CKVS Header table_size : %d\n"
               "CKVS Header threshold  : %d\n"
               "CKVS Header num_entries: %d\n",
               header->header_string,
               header->version,
               header->table_size,
               header->threshold_entries,
               header->num_entries);
}


void print_SHA(const char *prefix, const struct ckvs_sha *sha){
    if(prefix ==NULL && sha ==NULL) return;

    char buffer[SHA256_PRINTED_STRLEN];
    SHA256_to_string(sha, buffer);
    pps_printf("%-5s: %s\n", prefix, buffer);
}

void print_entry(const struct ckvs_entry* entry){
    if(entry ==NULL) return;


    pps_printf("    %-5s : "STR_LENGTH_FMT(CKVS_MAXKEYLEN)"\n", "Key", entry->key);
    pps_printf("    %-5s : off %lu len %lu\n", "Value", (size_t) entry->value_off, (size_t) entry->value_len);

    print_SHA("    Auth  " , &(entry->auth_key));
    print_SHA("    C2    " , &(entry->c2));
}


int ckvs_cmp_sha(const struct ckvs_sha *a, const struct ckvs_sha *b){
    M_REQUIRE_NON_NULL(a);
    M_REQUIRE_NON_NULL(b);

    return memcmp(a->sha,b->sha,SHA256_DIGEST_LENGTH);
}




/**
 * @brief Decodes a printable hex-encoded string into the corresponding value in a byte array.
 *
 * @param in (const char*) pointer to the input char array
 * @param buf (uint8_t*) pointer to the output byte buffer,
 * assumed to be large enough to store the decoded value.
 * @return int, the number of written bytes, or -1 in case of error
 *
 * @see hex_encode for the inverse operation
 */
int hex_decode(const char *in, uint8_t *buf){

    if(in==NULL || buf==NULL) return -1;

    char hexValue[3];
    int counter=0;
    while(*in != '\0'){
        if(strlen(in)%2!=0){
            hexValue[0] = '0';
            hexValue[1] = in[0];
            hexValue[2] = '\0';
            in +=1; //next byte
        }
        else{
            strncpy(hexValue,in,2);
            in +=2; //next byte
        }
        unsigned long result =  strtoul(hexValue, NULL, 16);
        if (result == ULONG_MAX) return -1;
        *buf = (uint8_t) result;
        counter++;
        buf++; //next elem
    }


    return counter;
}




/**
 * @brief Decodes a ckvs_sha from its printable hex-encoded representation.
 *
 * @param in (const char*) pointer to the char buffer
 * @param sha (struct ckvs_sha*) pointer to the output hash
 * @return int, the number of written bytes, or -1 in case of error
 *
 * @see SHA256_to_string for the inverse operation
 */
int SHA256_from_string(const char *in, struct ckvs_sha *sha){
    if(in==NULL || sha ==NULL) return -1;
    return hex_decode(in,sha->sha);
}
