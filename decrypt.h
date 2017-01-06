#define _GNU_SOURCE
#include <crypt.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>

#define DEBUG_INFO 1
#define DEBUG_DEBUG 2
#define DEBUG_WARNING 3
#define DEBUG_ERROR 4

#ifdef DEBUG_LEVEL
#define DEBUG_OUTPUT(level, format, ...) (level > DEBUG_LEVEL)?printf(format, ##__VA_ARGS__):0;
#else
#define DEBUG_OUTPUT
#endif

typedef struct tag_main_data {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int is_completed;
    int key_was_got;
    int active_worker_num;
    int *worker_events;
    char *result_key;
}main_data_s;

typedef struct tag_worker_data {
    pthread_mutext_t mutex;
    pthread_cond_t cond;
    int id;
    int *key_index;
    int max_len;
    int count;
    int running;
    main_data_s *main_data;
}worker_data_s;

