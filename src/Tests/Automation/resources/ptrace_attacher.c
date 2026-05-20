#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Started before owLSM (anti-tampering) so this process is not in protected_processes.
 * Reads one line: target PID, then execs strace -p <pid>.
 */
int main(void)
{
    char buf[64];

    if (!fgets(buf, sizeof(buf), stdin))
    {
        return 1;
    }

    int pid = atoi(buf);
    if (pid <= 0)
    {
        return 1;
    }

    char pidstr[32];
    if (snprintf(pidstr, sizeof(pidstr), "%d", pid) >= (int)sizeof(pidstr))
    {
        return 1;
    }

    execlp("strace", "strace", "-p", pidstr, (char *)NULL);
    perror("execlp strace");
    return 1;
}
