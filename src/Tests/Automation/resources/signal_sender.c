#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

int main(void)
{
    char buf[128];

    while (fgets(buf, sizeof(buf), stdin))
    {
        int pid = 0, signum = SIGKILL;
        int n = sscanf(buf, "%d %d", &pid, &signum);
        if (n >= 1 && pid > 0)
        {
            kill(pid, signum);
            if (n == 1)
                break; /* single-pid mode: exit after one kill */
        }
    }

    return 0;
}
