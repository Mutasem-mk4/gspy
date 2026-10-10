/* Controlled local witness for a genuine recorded procscope CLI session. */
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static void checked(int result, const char *operation) {
    if (result < 0) { perror(operation); exit(1); }
}

int main(void) {
    sleep(1);
    int fd = open("demo-note.txt", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    checked(fd, "open");
    checked((int)write(fd, "controlled local demo\n", 22), "write");
    close(fd);
    sleep(1);
    pid_t child = fork();
    checked(child, "fork");
    if (child == 0) {
        execl("/bin/echo", "echo", "Child process completed", (char *)NULL);
        perror("exec");
        _exit(1);
    }
    int status;
    checked(waitpid(child, &status, 0), "waitpid");
    if (!WIFEXITED(status) || WEXITSTATUS(status)) return 1;
    sleep(1);
    int server = socket(AF_INET, SOCK_STREAM, 0);
    checked(server, "server socket");
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = 0};
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    checked(bind(server, (struct sockaddr *)&address, sizeof(address)), "bind");
    checked(listen(server, 1), "listen");
    socklen_t size = sizeof(address);
    checked(getsockname(server, (struct sockaddr *)&address, &size), "getsockname");
    int client = socket(AF_INET, SOCK_STREAM, 0);
    checked(client, "client socket");
    checked(connect(client, (struct sockaddr *)&address, size), "connect");
    int accepted = accept(server, NULL, NULL);
    checked(accepted, "accept");
    close(accepted);
    close(client);
    close(server);
    sleep(1);
    checked(rename("demo-note.txt", "demo-renamed.txt"), "rename");
    sleep(1);
    checked(unlink("demo-renamed.txt"), "unlink");
    sleep(1);
    return 0;
}
