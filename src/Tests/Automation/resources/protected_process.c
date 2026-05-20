#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(void)
{
    char buf[64];

    while (fgets(buf, sizeof(buf), stdin))
    {
        if (buf[0] == '1')
            break;
    }

    pid_t child_pid = fork();
    if (child_pid == 0)
    {
        execlp("sleep", "sleep", "15", NULL);
        perror("execlp");
        exit(1);
    }

    printf("%d\n", (int)child_pid);
    fflush(stdout);

    while (fgets(buf, sizeof(buf), stdin))
    {
        if (buf[0] == '2')
            break;
    }

    int pipefd[2];
    if (pipe(pipefd) != 0)
    {
        perror("pipe");
        exit(1);
    }

    pid_t intermediate = fork();
    if (intermediate == 0)
    {
        close(pipefd[0]);

        pid_t grandchild = fork();
        if (grandchild == 0)
        {
            close(pipefd[1]);
            sleep(15);
            exit(0);
        }

        const ssize_t n = write(pipefd[1], &grandchild, sizeof(pid_t));
        if (n != (ssize_t)sizeof(pid_t))
        {
            perror("write");
            close(pipefd[1]);
            exit(1);
        }
        close(pipefd[1]);
        exit(0);
    }

    close(pipefd[1]);

    pid_t grandchild_pid;
    const ssize_t nr = read(pipefd[0], &grandchild_pid, sizeof(pid_t));
    if (nr != (ssize_t)sizeof(pid_t))
    {
        perror("read");
        close(pipefd[0]);
        exit(1);
    }
    close(pipefd[0]);

    waitpid(intermediate, NULL, 0);

    printf("%d\n", (int)grandchild_pid);
    fflush(stdout);

    while (1)
        sleep(60);

    return 0;
}
