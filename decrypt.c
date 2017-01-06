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

 
