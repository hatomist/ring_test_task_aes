#include "main.h"

#include <gcrypt.h>
#include <getopt.h>
#include <stdio.h>


static char* program_name;

static const char* help_string = "Usage: %s [-deh] file password [out]\n"
                                 "Encrypt or decrypt file using AES-256 encryption algorithm.\n"
                                 "\n"
                                 "-d              Decrypt given file \n"
                                 "-e              Encrypt given file (default)\n"
                                 "-h              Show this page\n"
                                 "\n"
                                 "Exit status:\n"
                                 " 0  if OK,\n"
                                 " 1  if critical error.";

struct {
    char mode;              // decrypt ('D') or encrypt ('E'), defaults to guess by magic number
    char* password;         // encryption/decryption password
    char* in_file_path;     // input file path
    char* out_file_path;    // output file path, defaults to "in_file_path.aes" if in encryption mode and to
                            // "in_file_path" without ".aes" part if possible, otherwise "in_file_path.decrypted"
} config = {'g', NULL, NULL, NULL};


/** Print help */
static void help()
{
    (void)fprintf(stdout, help_string, program_name);
}

/** Cleanup and exit program.
 * @param ret return code
 */
static void cleanup(ret) {
    exit(ret);
}

/** Parse operation from cli arguments.
 *
 * @param opt opt
 * @return
 */
static int parsearg_op(int opt)
{
    switch (opt) { // NOLINT(hicpp-multiway-paths-covered)
        case 'd':
        case 'e':
            if (config.mode != 'g')  // already selected mode
            {
                (void)fprintf(stderr,"Error: mode selection option was specified more than once\n");
                return 1;
            }
            config.mode = (char)opt;
            return 0;
        case 'h':
            help();
            cleanup(0);
    }
    return 0;
}

/** Parse cli arguments for each operation.
 * @param argc argc
 * @param argv argv
 * @return 0 on success, 1 on error
 */
static int parseargs(int argc, char *argv[])
{
    int opt = 0;
    int ret;
    while ((opt = getopt(argc, argv, "+edh")) != -1)
    {
        if (opt == '?') {
            // unknown option, getopt printed an error
            return 1;
        }
        ret = parsearg_op(opt);
        if (ret)
            return ret;
    }

    if (argc - optind < MIN_POS_ARG_NUM)
    {
        (void)fprintf(stderr,"Error: not enough positional arguments\n");
        help();
        return(1);
    }

    if (argc - optind > MAX_POS_ARG_NUM)
    {
        (void)fprintf(stderr,"Error: too many positional arguments\n");
        help();
        return(1);
    }

    config.in_file_path = argv[optind++];
    config.password = argv[optind++];
    config.out_file_path = optind < argc ? argv[optind++] : NULL;  // optional arg, set only if specified

    return 0;
}

int main(int argc, char* argv[]) {
    program_name = argv[0];
    int ret = 0;

    ret = parseargs(argc, argv);
    if (ret != 0) {
        cleanup(ret);
    }

    cleanup(ret);
}

