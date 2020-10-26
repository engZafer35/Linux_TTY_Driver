#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define DEV_PATH "/dev/ttyZ"

void start_test(void)
{
    int fd;
    char str[] = "tty test";

    fd = open(DEV_PATH, O_RDWR);
    if (0 > fd)
    {
        printf("First File could not be opened err %d", errno);
    }
    else
    {
        write(fd,str,strlen(str));
        close(fd);
    }
}

int main()
{
    printf("----- TTY Test ----- \n");

    start_test();
    return 0;
}
