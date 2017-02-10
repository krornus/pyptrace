#include <stdio.h>
#define SIZE 1024

int main()
{
    char a[SIZE];
    fgets(a, SIZE, stdin);

    printf("stdin: '%s'\n", a);
}
