
#define SRCLEN 20
#define DSTLEN SRCLEN

int main(int argc, char **argv) {

    char src[SRCLEN], dst[DSTLEN];

    for (int i = 0; i < SRCLEN; i++) {
        dst[i] = src[i];
    }
}

