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

