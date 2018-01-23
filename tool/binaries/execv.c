#include <unistd.h>

#define CHILD "/home/spowell/research/pyitrace/tool/binaries/execv_child"

int main(int argc, char **argv) {
    execve(CHILD, NULL, NULL);
    return 0;
}
