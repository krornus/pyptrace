#include <stdio.h>
int main(int argc, char **argv)
{
    if(argc < 2)
    {
        printf("no arguments received.\n");
        return 0;
    }
    printf("recieved %d args\n", argc);
    
    for(int i = 0; i < argc; i++)
    {
        printf("argv[%d]: '%s'\n", i, argv[i]);
    }
    return 0;
}
