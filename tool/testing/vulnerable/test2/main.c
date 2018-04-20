#include <string.h>

#define DSTLEN 10

int main(int argc, char **argv) {

    char *src = "this is a test string";
    char dst[DSTLEN];

    strcpy(dst,src);
}

