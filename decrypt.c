#include "decrypt.h"

char *expected_result = 0;
int expected_length = 0;
char *curr_salt = 0;
char dic[128];
int dic_len = 0;

void index_to_password(int *key_index, int max_len, char *password)
{
    do {
        *password ++ = dic[*key_index ++];
    } while(*key_index >= 0);
    *password = '\0';
}

int next_password(int *key_index, int max_len, int base, char *password)
{
    int i = 0;
    do {
        key_index[i]++;
        if (key_index[i] >= base) {
            key_index[i] = key_index[i] % base;
            password[i] = dic[key_index[i]];
            i ++;
            if (i >= max_len) {
                return -1;
            }
            continue;
        } else {
            password[i] = dic[key_index[i]];
            break;
        }
    } while(1);
    return 0;
}

int diff_to_max_index(int *key_index, int max_len, int base)
{
    int weight = 1, result = 1, i = 0;
    for (i = 0; i < max_len; i ++) {
        result += (base - 1 - key_index[i]) * weight;
        weight *= base;
    }
    DEBUG_OUTPUT(DEBUG_DEBUG, "step exceed for len=%d, diff to max value is: %d\r\n", max_len, result);
    return result;
}

int step_forward(int *key_index, int max_len, int base, int step)
{
    int i = 0, j = 0, mod = 0, weight = 0, ret = 0, ori_step = step, exceed = 0;
    char password[128];
    int *restore = malloc(sizeof(int)*max_len);
    assert(0 != restore);
   
    assert(max_len < 128);
    index_to_password(key_index, max_len, password);
    //DEBUG_OUTPUT(DEBUG_WARNING, "current step is: %s\r\n", password);
    DEBUG_OUTPUT(DEBUG_DEBUG, "input step is: %d\r\n", step);
    DEBUG_OUTPUT(DEBUG_ERROR, "password of current step is: %s\r\n", password);
#if DEBUG_DEBUG >= DEBUG_LEVEL
    printf("index of current step is: ");
    for (i = 0; i < max_len; i ++) {
        if (0 <= key_index[i]) {
            printf("%02d ", key_index[i]);
            continue;
        }
        break;
    }
    printf("\r\n");
#endif
    memcpy(restore, key_index, sizeof(int)*max_len);
    for (i = 0; i < max_len && 0 != step; i ++) {
        mod = step % base;
        assert(key_index[i]>=0);
        key_index[i] += mod;

        j = i;
        while(key_index[i] >= base) {
            if (j + 1 < max_len) {
                key_index[j] = key_index[j] % base;
                key_index[++j]++;
            } else {
                memcpy(key_index, restore, sizeof(int)*max_len);
                return diff_to_max_index(key_index, max_len, base);
            }
        }
        step /= base;
    }
    if (0 != step && i >= max_len) {
        memcpy(key_index, restore, sizeof(int)*max_len);
        return diff_to_max_index(key_index, max_len, base);
    }
    return 0;
}

void *worker(void *args)
{
    int i = 0; 
    int ret = 0;
    struct crypt_data local_crypt_data;
    worker_data_s *worker_data = (worker_data_s*)args;
    char *curr_key = malloc(worker_data->max_len + 1);
    assert(0 != curr_key);

    memset(curr_key, 0, worker_data->max_len + 1);
    local_crypt_data.initialized = 0;
    
    pthread_mutex_lock(&worker_data->mutex);
    do {
        index_to_password(worker_data->key_index, worker_data->max_len, curr_key);
        for(i = 0; i < worker_data->count; i ++) {
            DEBUG_OUTPUT(DEBUG_INFO, "[%p] current key is: %s\r\n", worker_data, curr_key);
            if (0 == memcmp(expected_result, crypt_r(curr_key, curr_salt, &local_crypt_data), expected_length)) {
                pthread_mutex_lock(&worker_data->main_data->mutex);
                worker_data->main_data->key_was_got = 1;
                strncpy(worker_data->main_data->result_key, curr_key, worker_data->max_len);
                pthread_mutex_unlock(&worker_data->main_data->mutex);
                break;
            }
            ret = next_password(worker_data->key_index, worker_data->max_len, dic_len, curr_key);
            if (0 != ret) printf("[%p]get next password failed when key is: %s\r\n", worker_data, curr_key);
        }

        DEBUG_OUTPUT(DEBUG_WARNING, "[%p] complete current area.\r\n", worker_data);
        pthread_mutex_lock(&worker_data->main_data->mutex);
        if (worker_data->main_data->is_completed || worker_data->main_data->key_was_got) {
            pthread_mutex_unlock(&worker_data->main_data->mutex);
            break;
        }
        worker_data->main_data->worker_events[worker_data->id] = 1;
        pthread_signal(&worker_data->main_data->cond);
        DEBUG_OUTPUT(DEBUG_WARNING, "notify to main\r\n");
        pthread_mutex_unlock(&worker_data->main_data->mutex);

        pthread_cond_wait(&worker_data->cond, &worker_data->mutex);
        DEBUG_OUTPUT(DEBUG_WARNING, "child get cond\r\n");
    } while(worker_data->running);
    pthread_mutex_unlock(&worker_data->mutex);

    free(curr_key);
    pthread_mutex_lock(&worker_data->main_data->mutex);
    worker_data->main_data->active_worker_num --;
    pthread_cond_signal(&worker_data->main_data->cond);
    pthread_mutex_unlock(&worker_data->main_data->mutex);
    return 0;
}
             
void decrypt_password(int max_worker_num, int min_key_len, int max_key_len, int step)
{
    pthread_t tid;
    pthread_attr_t tattr;
    worker_data_s *worker_data_array;
    main_data_s *main_data;
    int i = 0;
    int ret = 0;
    int diff = 0;
    int *curr_key_index = 0;
    int curr_key_len = min_key_len;

    pthread_attr_init(&tattr);

    main_data = malloc(sizeof(main_data_s));
    assert(0 != main_data);
    pthread_mutex_init(&main_data->mutex, 0);
    pthread_cond_init(&main_data->cond, 0);
    main_data->is_completed = 0;
    main_data->key_was_got = 0;
    main_data->active_worker_num = 0;
    main_data->worker_events = malloc(sizeof(int)*max_worker_num);
    assert(0 != main_data->worker_events);
    memset(main_data->worker_events, 0, sizeof(int)*max_worker_num);
    main_data->result_key = malloc(max_key_len + 1);
    assert(0 != main_data->result_key);
    memset(main_data->result_key, 0, max_key_len + 1);

    curr_key_index = (int *)malloc(sizeof(int)*(max_key_len + 1));
    assert(0 != curr_key_index);
    memset(curr_key_index, 0, sizeof(int)*(max_key_len + 1));
    for(i = min_key_len; i <= max_key_len; i ++) { 
        curr_key_index[i] = -1;
    }

    worker_data_array = malloc(sizeof(worker_data_s)*max_worker_num);
    assert(0 != worker_data_array);

    pthread_mutex_lock(&main_data->mutex);
    for (i = 0; i < max_worker_num; i ++) {
        pthread_mutex_init(&(worker_data_array[i].mutex), 0);
        pthread_cond_init(&(worker_data_array[i].cond), 0);
        worker_data_array[i].id = i;
        worker_data_array[i].main_data = main_data;
        worker_data_array[i].max_len = max_key_len;
        worker_data_array[i].key_index = malloc(sizeof(int)*(max_key_len + 1));
        assert(0 != worker_data_array[i].key_index);
        memcpy(worker_data_array[i].key_index, curr_key_index, sizeof(int)*(max_key_len + 1));

        diff = step_forward(curr_key_index, curr_key_len, dic_len, step);
        if (0 != diff) {
            if (curr_key_len >= max_key_len) {
                main_data->is_completed = 1;
            } else {
                curr_key_len ++;
                memset(curr_key_index, 0, sizeof(int)*curr_key_len);
            }
            worker_data_array[i].count = diff;
        } else {
            worker_data_array[i].count = step;
        }
        worker_data_array[i].running = 1;

        ret = pthread_create(&tid, &tattr, worker, (void *)&worker_data_array[i]);
        assert(0 == ret);
        main_data->active_worker_num ++;
        if (1 == main_data->is_completed) break;
    }

    do {
        pthread_cond_wait(&main_data->cond, &main_data->mutex);
        
        DEBUG_OUTPUT(DEBUG_WARNING, "main get cond\r\n");
        for (i = 0; i  < main_data->active_worker_num; i ++) {
            if (!main_data->worker_events[i]) continue;
            main_data->worker_events[i] = 0;

            pthread_mutex_lock(&worker_data_array[i].mutex);
            if (!main_data->key_was_got && ! main_data->is_completed) { 
                memcpy(worker_data_array[i].key_index, curr_key_index, sizeof(int)*(max_key_len + 1));

                diff = step_forward(curr_key_index, max_key_len, dic_len, step);
                if (0 != diff) {
                    if (curr_key_len >= max_key_len) {
                        main_data->is_completed = 1;
                    } else {
                        curr_key_len ++;
                        memset(curr_key_index, 0, sizeof(int)*curr_key_len);
                    }
                    worker_data_array[i].count = diff + 1;
                } else {
                    worker_data_array[i].count = step;
                }
                pthread_cond_signal(&worker_data_array[i].cond);
                DEBUG_OUTPUT(DEBUG_WARNING, "notify to child\r\n");
            } else {
               worker_data_array[i].running = 0;
            }
            pthread_mutex_unlock(&worker_data_array[i].mutex);
        }
    }while(main_data->active_worker_num);
    pthread_mutex_unlock(&main_data->mutex);

    if (!main_data->key_was_got) printf("the password was not found!\r\n");
    else printf("the password is: %s\r\n", main_data->result_key);

    free(curr_key_index);
    pthread_mutex_destroy(&main_data->mutex);
    pthread_cond_destroy(&main_data->cond);
    free(main_data->result_key);
    free(main_data->worker_events);
    free(main_data);
    for (i = 0; i < max_worker_num; i ++) {
        free(worker_data_array[i].key_index);
        pthread_mutex_destroy(&worker_data_array[i].mutex);
        pthread_cond_destroy(&worker_data_array[i].cond);
    }
    free(worker_data_array);
    pthread_attr_destroy(&tattr);
}

int main(int argc, char *argv[])
{
    char in_salt[16];
    char in_crypted[128];
    int encrypt_method;
    int max_worker = 0;
    int min_key_len = 0;
    int max_key_len = 0;
    int step = 0;

    printf("Please input the dictionary: ");
    scanf("%127s", dic);
    printf("%s\r\n", dic);
    if((dic_len = strlen(dic)) <= 0) {
        printf("The dictionary is null.\r\n");
        goto exit;
    }

    printf("Please input the encryption method id(5 or 6): ");
    scanf("%d", &encrypt_method);
    if(5 != encrypt_method && 6 != encrypt_method) {
        //
        goto exit;
    }

    printf("Please input the salt: ");
    scanf("%8s", in_salt);
    printf("%s\r\n", in_salt);
    if (8 != strlen(in_salt)) {
        //
        goto exit;
    }

    printf("Please input the encrypted string: ");
    scanf("%127s", in_crypted);
    printf("%s\r\n", in_crypted);
    if(strlen(in_crypted) <= 0) {
        //
        goto exit;
    }

    printf("Please input the worker_num: ");
    scanf("%d", &max_worker);
    printf("%d\r\n", max_worker);
    printf("Please input the min_key_len: ");
    scanf("%d", &min_key_len);
    printf("%d\r\n", min_key_len);
    printf("Please input the max_key_len: ");
    scanf("%d", &max_key_len);
    printf("%d\r\n", max_key_len);
    printf("Please input the step: ");
    scanf("%d", &step);
    printf("%d\r\n", step);

    curr_salt = malloc(32);
    assert(0 != curr_salt);
    sprintf(curr_salt, "$%d$%s$", encrypt_method, in_salt);
    DEBUG_OUTPUT(DEBUG_WARNING, "current salt is: %s\r\n", curr_salt);
    expected_result = malloc(256);
    assert(0 != expected_result);
    expected_length = sprintf(expected_result, "%s%s", curr_salt, in_crypted);
    DEBUG_OUTPUT(DEBUG_WARNING, "expected result[length=%d] is: %s\r\n", expected_length, expected_result);
    decryp_password(max_worker, min_key_len, max_key_len, step);
exit:
    free(curr_salt);
    free(expected_result);
 
    return 0;
}
