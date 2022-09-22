/*
 * cryptkvs -- main ; argument parsing and dispatch ; etc.
 */

#include <stdio.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_client.h"
#include "ckvs_httpd.h"
#include "ckvs_utils.h"

/* *************************************************** *
 * TODO WEEK 09-11: Add then augment usage messages    *
 * *************************************************** */
typedef int (*ckvs_command)(const char* filename, int optargc, char* optargv[]);

struct ckvs_command_mapping{
    const char *nom;
    const char *description;
    ckvs_command local;
    ckvs_command client;
};

const struct ckvs_command_mapping commands[] = {
        {"stats","- cryptkvs [<database>|<url>] stats",ckvs_local_stats, ckvs_client_stats},
        {"get","- cryptkvs [<database>|<url>] get <key> <password>",ckvs_local_get, ckvs_client_get},
        {"set","- cryptkvs [<database>|<url>] set <key> <password> <filename>",ckvs_local_set, ckvs_client_set},
        {"new","- cryptkvs [<database>|<url>] new <key> <password>",ckvs_local_new, ckvs_client_new},
        {"httpd","- cryptkvs [<database>] httpd <url>",ckvs_httpd_mainloop, NULL}
};
/* *************************************************** *
 * TODO WEEK 04-07: add message                        *
 * TODO WEEK 09: Refactor usage()                      *
 * *************************************************** */
static void usage(const char *execname, int err)
{
    if (err == ERR_INVALID_COMMAND) {
        pps_printf("Available commands:\n");
        for(size_t i = 0;i<sizeof(commands)/sizeof(commands[0]);i++){
            pps_printf("%s\n", commands[i].description);
        }
        pps_printf("\n");
    } else if (err >= 0 && err < ERR_NB_ERR) {
        pps_printf("%s exited with error: %s\n\n\n", execname, ERR_MESSAGES[err]);
    } else {
        pps_printf("%s exited with error: %d (out of range)\n\n\n", execname, err);
    }
}

/* *************************************************** *
 * TODO WEEK 04-11: Add more commands                  *
 * TODO WEEK 09: Refactor ckvs_local_*** commands      *
 * *************************************************** */
/**
 * @brief Runs the command requested by the user in the command line, or returns ERR_INVALID_COMMAND if the command is not found.
 *
 * @param argc (int) the number of arguments in the command line
 * @param argv (char*[]) the arguments of the command line, as passed to main()
 */
int ckvs_do_one_cmd(int argc, char *argv[])
{
    if (argc < 3) return ERR_INVALID_COMMAND;

    const char *prefix_clientNotCrypted = "http://";
    const char *prefix_clientCrypted = "https://";

    const char* db_filename = argv[1];
    const char* cmd = argv[2];
    int optargc = argc - 3;
    char **optargv = argv+3; //TODO WEEK09 given by teacher but not compalling char* optargv[] = argv + 3;
    for(size_t i = 0;i<sizeof(commands)/sizeof(commands[0]);i++){
        if(!strcmp(cmd,commands[i].nom)){
            if(!strncmp(db_filename, prefix_clientNotCrypted, strlen(prefix_clientNotCrypted)) || !strncmp(db_filename, prefix_clientCrypted, strlen(prefix_clientCrypted))){
                if(commands[i].client==NULL) return ERR_INVALID_COMMAND;
                return commands[i].client(db_filename, optargc, optargv);
            } else {
                return commands[i].local(db_filename, optargc, optargv);
            }
        }
    }
    return ERR_INVALID_COMMAND;
}

#ifndef FUZZ
/**
 * @brief main function, runs the requested command and prints the resulting error if any.
 */
int main(int argc, char *argv[])
{
   int ret = ckvs_do_one_cmd(argc, argv);
    if (ret != ERR_NONE) {
        usage(argv[0], ret);
    }
    return ret;
}
#endif
