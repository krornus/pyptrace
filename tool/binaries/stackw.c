void foo(int *x);

int main(int argc, char **argv) {
    int x;
    foo(&x);
}

void foo(int *x) {
    *x = 1;
}
