#include <unistd.h>

#define CHILD "/home/spowell/research/pyitrace/tool/binaries/execv_child"

int main(int argc, char **argv) {
    execvp(CHILD, NULL);
    return 0;
}
