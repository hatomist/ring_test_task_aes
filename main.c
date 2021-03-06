#include "main.h"

#include <gcrypt.h>
#include <getopt.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <libgen.h>
#include "unistd.h"


/* Header format
 * ================================================================================
 * | Magic number (4 bytes) | File size (8 bytes, decimal) | CRC32 (4 bytes, hex) |
 * |        0x00-0x03       |         0x04 - 0x0B          |      0x0C - 0x0F     |
 * ================================================================================
 */


static char* program_name;

static const char* help_string = "Usage: %s [-deh] file key [out-file/path]\n"
                                 "Encrypt or decrypt file using AES-256 encryption algorithm.\n"
                                 "\n"
                                 "-d              Decrypt given file \n"
                                 "-e              Encrypt given file (default)\n"
                                 "-f              Overwrite files\n"
                                 "-h              Show this page\n"
                                 "\n"
                                 "Exit status:\n"
                                 " 0  if OK,\n"
                                 " 1  if critical error.\n";

/** randomly generated initialization vector for aes256-cfb */
static const uint8_t iv[16] = {0x6e, 0x3a, 0x14, 0x15, 0x3f, 0x79, 0xfa, 0xc4, 0x0e, 0x2e, 0x72, 0xd6, 0x5d, 0x6c, 0x18, 0x86};

struct {
    char mode;              // decrypt ('D') or encrypt ('E'), defaults to guess by magic number
    int overwrite;          // force file overwrite
    char* key_string;       // encryption/decryption key string
    uint8_t key[32];        // encryption/decryption key
    char* in_file_path;     // input file path
    char* out_file_path;    // output file or directory path, defaults to "in_file_path.aes" if in encryption mode and to
                            // "in_file_path" without ".aes" part if possible, otherwise "in_file_path.dec"
} config = {'g', 0, NULL, {}, NULL, NULL};


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

/** Check if file exists and user allows to overwrite it
 * @param path path to file
 * @return 1 if file could be overwritten/created, else 0
 * */
static int check_file_overwrite(const char *path)
{
    if(access(path, F_OK) != -1)
    {
        if (!config.overwrite)
            return 0;
    }
    return 1;
}

/** Check if directory is found on given path
 * @param path path
 * @return 0 if not directory, else 1
 */
static int is_dir(const char *path)
{
    struct stat obj_stat;
    stat(path, &obj_stat);
    return !!(S_ISDIR(obj_stat.st_mode));
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
        case 'f':
            config.overwrite = 1;
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
    while ((opt = getopt(argc, argv, "+defh")) != -1)
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
        return 1;
    }

    if (argc - optind > MAX_POS_ARG_NUM)
    {
        (void)fprintf(stderr,"Error: too many positional arguments\n");
        help();
        return 1;
    }

    config.in_file_path = argv[optind++];
    config.key_string = argv[optind++];

    if (strlen(config.key_string) != 64)
    {
        (void)fprintf(stderr,"Error: not 256-bit hex-encoded key\n");
        return 1;
    }

    // easy way to check if given string is hex-string and will be correctly decoded by sscanf
    char *s = config.key_string;
    for (size_t i = 0; i < 64; i++)
    {
        if (!(  (s[i] <= '9' && s[i] >= '0') ||
                (s[i] <= 'f' && s[i] >= 'a') ||
                (s[i] <= 'F' && s[i] >= 'A')))
        {
            (void)fprintf(stderr,"Error: not 256-bit hex-encoded key\n");
            return 1;
        }
    }

    for (size_t i = 0; i < 32; i++)
    {
        sscanf(s, "%2hhx", &config.key[i]);
        s += 2;
    }

    config.out_file_path = optind < argc ? argv[optind++] : NULL;  // optional arg, set only if specified

    return 0;
}

/** Show information about file access error
 * @param filename file name
 * @return errno
 */
static int file_parse_errno(const char *filename)
{
    switch (errno)
    {
        case EISDIR:
            (void)fprintf(stderr, "\"%s\" is a directory!\n", filename);
            return errno;
        case ENOENT:
        case EFAULT:
            (void)fprintf(stderr, "Bad file path entered: \"%s\"\n", filename);
            return errno;
        case EACCES:
            (void)fprintf(stderr, "Cannot open the file \"%s\": insufficient permissions\n", filename);
            return errno;
        default:
            (void)fprintf(stderr, "Cannot open the file \"%s\": unknown error %d\n", filename, errno);
            return errno;
    }
}

/** Get base path to determine output file path
 * @return base path
 */
static char* get_base_path()
{
    char *base_path;
    if (config.out_file_path != NULL && is_dir(config.out_file_path))
    {
        // allocate char array for out file dir path, '/' char, filename and '\0' to do the rest with next if-clause
        base_path = malloc(strlen(config.out_file_path) + 1 + strlen(basename(config.in_file_path)) + 1);
        strcpy(base_path, config.out_file_path);
        base_path[strlen(config.out_file_path)] = '/';
        strcpy(base_path + strlen(config.out_file_path) + 1, basename(config.in_file_path));
        config.out_file_path = NULL;
    } else {
        base_path = config.in_file_path;
    }
    return base_path;
}

/** Decrypt file via given key and save
 * @return error code
 */
static int decrypt()
{
    // automatically set out filename if not specified
    char *base_path = get_base_path();

    if (config.out_file_path == NULL)
    {
        size_t base_path_strlen = strlen(base_path);

        // 5 - len of ".aes" and any other symbol
        if (base_path_strlen > 5 && !(strcmp(base_path + base_path_strlen - 4, ".aes")))
        {
            config.out_file_path = malloc(base_path_strlen + 1);
            strcpy(config.out_file_path, base_path);
            config.out_file_path[base_path_strlen - 4] = 0;
        } else {
            config.out_file_path = malloc(base_path_strlen + 4 + 1);  // 4 - len of ".aes", 1 - for \0
            strcpy(config.out_file_path, config.in_file_path);
            strcpy(config.out_file_path + base_path_strlen, ".dec");
        }
    }

    // open files and check for errors
    errno = 0;
    FILE *in_file = fopen(config.in_file_path, "rb");
    if (in_file == NULL)
        return file_parse_errno(config.in_file_path);

    if (!check_file_overwrite(config.out_file_path))
    {
        (void)fprintf(stderr,"File already exists, aborting...\n");
        return 1;
    }

    errno = 0;
    FILE *out_file = fopen(config.out_file_path, "wb+");
    if (out_file == NULL)
        return file_parse_errno(config.out_file_path);

    // initialize crc32 and aes256 libgcrypt handlers
    gcry_md_hd_t gcry_md_hd;
    gcry_md_open(&gcry_md_hd, GCRY_MD_CRC32, 0);

    gcry_cipher_hd_t gcry_cipher_hd;
    gcry_cipher_open(&gcry_cipher_hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, 0);
    gcry_cipher_setkey(gcry_cipher_hd, config.key, 32);  // 32 bytes * 8 = 256 bit key
    gcry_cipher_setiv(gcry_cipher_hd, iv, 16);

    fseek(in_file, 4, SEEK_SET);
    uint64_t file_size;
    fread(&file_size, 8, 1, in_file);
    file_size = ntohll(file_size);
    uint32_t crc32_given;
    fread(&crc32_given, 4, 1, in_file);

    uint8_t buf[FILE_BUF_SIZE];

    size_t read_bytes;
    do {
        read_bytes = fread(buf, 1, FILE_BUF_SIZE, in_file);
        gcry_cipher_decrypt(gcry_cipher_hd, buf, read_bytes, NULL, 0);
        gcry_md_write(gcry_md_hd, buf, read_bytes);
        fwrite(buf, read_bytes, 1, out_file);
    } while (read_bytes > 0);

    unsigned char *crc32_res = gcry_md_read(gcry_md_hd, 0);
    if (*((uint32_t *)crc32_res) != crc32_given)
    {
        (void)fprintf(stderr,"Error: CRC32 does not match!\n");
        fclose(out_file);
        remove(config.out_file_path);
        return 1;
    }

    fseek(out_file, 0, SEEK_SET);
    ftruncate(fileno(out_file), file_size);

    gcry_md_close(gcry_md_hd);
    gcry_cipher_close(gcry_cipher_hd);
    fclose(in_file);
    fclose(out_file);

    (void)fprintf(stdout,"Successfully decrypted file\n");
    return 0;
}

/** Encrypt file via given key and save
 * @return error code
 */
static int encrypt()
{
    // automatically set out filename if not specified
    char *base_path = get_base_path();

    if (config.out_file_path == NULL)
    {
        size_t base_path_strlen = strlen(base_path);
        config.out_file_path = malloc(base_path_strlen + 4 + 1);  // 4 - len of ".aes", 1 - for \0
        strcpy(config.out_file_path, base_path);
        strcpy(config.out_file_path + base_path_strlen, ".aes");
    }

    if (!check_file_overwrite(config.out_file_path))
    {
        (void)fprintf(stderr,"File already exists, aborting...\n");
        return 1;
    }

    // open files and check for errors
    errno = 0;
    FILE *in_file = fopen(config.in_file_path, "rb");
    if (in_file == NULL)
        return file_parse_errno(config.in_file_path);

    errno = 0;
    FILE *out_file = fopen(config.out_file_path, "wb+");
    if (out_file == NULL)
        return file_parse_errno(config.out_file_path);

    uint32_t magic = htonl(MAGIC_NUMBER);
    fwrite(&magic, 4, 1, out_file);
    fseek(in_file, 0, SEEK_END);
    uint64_t file_size = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);
    file_size = htonll(file_size);

    fwrite(&file_size, 8, 1, out_file);

    fseek(out_file, 4, SEEK_CUR);  // skip 4 bytes for CRC32, we'll fill that later


    // initialize crc32 and aes256 libgcrypt handlers
    gcry_md_hd_t gcry_md_hd;
    gcry_md_open(&gcry_md_hd, GCRY_MD_CRC32, 0);

    gcry_cipher_hd_t gcry_cipher_hd;
    gcry_cipher_open(&gcry_cipher_hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, 0);
    gcry_cipher_setkey(gcry_cipher_hd, config.key, 32);  // 32 bytes * 8 = 256 bit key
    gcry_cipher_setiv(gcry_cipher_hd, iv, 16);



    // calculate crc32 and encrypt data by blocks of FILE_BUF_SIZE
    uint8_t buf[FILE_BUF_SIZE];

    size_t read_bytes;
    while ((read_bytes = fread(buf, 1, FILE_BUF_SIZE, in_file)) != 0) {
        size_t padding = (16 - (read_bytes % 16)) % 16;
        memset(buf + read_bytes, 0, padding);  // Block size must be multiple of 16 for AES256
        gcry_md_write(gcry_md_hd, buf, read_bytes + padding);
        gcry_cipher_encrypt(gcry_cipher_hd, buf, read_bytes + padding, NULL, 0);
        fwrite(buf, read_bytes + padding, 1, out_file);
    }

    unsigned char *crc32_res = gcry_md_read(gcry_md_hd, 0);

    fseek(out_file, 12, SEEK_SET);
    fwrite(crc32_res, 4, 1, out_file);

    gcry_md_close(gcry_md_hd);
    gcry_cipher_close(gcry_cipher_hd);

    uint8_t header[16];
    fseek(out_file, 0, SEEK_SET);
    fread(header, 16, 1, out_file);
    (void)fprintf(stdout, "Successfully encrypted file!\nFile header: %08X | %016lX | %08X\n",
                  ntohl(*((uint32_t *)&header[0])), ntohll(*((uint64_t *)&header[4])),
                  ntohl(*((uint32_t *)&header[12])));

    return 0;
}

/** Try to guess by magic number what to do with given file (encrypt or decrypt)
 * @return 0 on success, errno value on error
 */
static int guess()
{
    (void)fprintf(stdout, "WARNING: no command supplied. Trying to guess what you mean...\n");
    errno = 0;
    FILE *in_file = fopen(config.in_file_path, "rb");
    if (in_file == NULL)
        return file_parse_errno(config.in_file_path);

    fseek(in_file, 0, SEEK_END);
    size_t file_size = ftell(in_file);

    if (file_size < HEADER_SIZE)
    {
        (void)fprintf(stdout, "File size is less than header, encrypting file...\n");
        fclose(in_file);
        return encrypt();  // file size less than header, most probably unencrypted file
    }

    fseek(in_file, 0, SEEK_SET);

    uint32_t magic;
    fread(&magic, 4, 1, in_file);
    fclose(in_file);

    if (magic == htonl(MAGIC_NUMBER))
    {
        (void)fprintf(stdout, "Found magic number - decrypting file...\n");
        return decrypt();
    }
    else
    {
        (void)fprintf(stdout, "Magic number not found - encrypting file...\n");
        return encrypt();
    }
}

int main(int argc, char* argv[]) {
    program_name = argv[0];
    int ret = 0;

    ret = parseargs(argc, argv);
    if (ret != 0) {
        cleanup(ret);
    }

    switch (config.mode) {
        case 'd':
            ret = decrypt(); break;
        case 'e':
            ret = encrypt(); break;
        case 'g':
            ret = guess(); break;
    }

    cleanup(ret);
}

