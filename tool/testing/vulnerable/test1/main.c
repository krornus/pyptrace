#include <string.h>

#define SRCLEN 30
#define DSTLEN 10

int main(int argc, char **argv) {

    char src[SRCLEN], dst[DSTLEN];

    memset(src, 0, SRCLEN);

    for (int i = 0; i < SRCLEN; i++) {
        dst[i] = src[i];
    }
}

