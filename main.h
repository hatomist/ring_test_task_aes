#ifndef RING_TEST_TASK_AES_MAIN_H
#define RING_TEST_TASK_AES_MAIN_H

#define MAX_POS_ARG_NUM 3  // file path, password and out file path
#define MIN_POS_ARG_NUM 2  // file path and password
#define HEADER_SIZE 16
#define FILE_BUF_SIZE 4096
#define MAGIC_NUMBER 0xBABCBDBE

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

#endif //RING_TEST_TASK_AES_MAIN_H
