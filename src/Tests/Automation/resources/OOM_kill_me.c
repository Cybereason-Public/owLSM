#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

int main(void)
{
    char buf[64];

    while (fgets(buf, sizeof(buf), stdin))
    {
        if (buf[0] == '1')
            break;
    }

    int fd = open("/proc/self/oom_score_adj", O_WRONLY);
    if (fd >= 0)
    {
        const ssize_t n = write(fd, "1000", 4);
        if (n != 4)
        {
            perror("write oom_score_adj");
        }
        close(fd);
    }

    while (1)
    {
        char *p = malloc(1024 * 1024);
        if (p)
            memset(p, 1, 1024 * 1024);
    }

    return 0;
}
