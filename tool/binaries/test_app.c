#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    int value;

    char buf[20];

    value = 1;
    value = 0x616161;

    if(argc == 0)
    {
        printf("No args\n");
    }
    else
    {
        for(int i = 0; i < argc; i++)
        {
            printf("argv[%d]: '%s'\n", i, argv[i]);
        }
    }

    gets(buf);
    printf("buf: '%s' (len %lu)\n", buf, strlen(buf));
    
    return 0;
}
