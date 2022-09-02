#include <iostream>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#define PORT 8124

enum State
{
    start,
    inited,
    authed,
    error,
    closed
};

int debug = 1;

static void reply_and_update(int socketConnection, State *instanceState, const char *output, State newState)
{
#if 1
    *instanceState = newState;
    send(socketConnection, output, strlen(output), 0);
#else
    send(socketConnection, output, strlen(output), 0);
    *instanceState = newState;
#endif
}

void protocolInstance(int socketConnection)
{

    pid_t pid = getpid();

    State *instanceState;
    instanceState = (State *)malloc(sizeof(State));
    *instanceState = start;

    std::cout << std::hex << instanceState << std::dec << std::endl;

    char buffer[1024] = {0};
    while (read(socketConnection, buffer, 1024) > 0)
    {
        if (debug)
        {
            printf("Got: %s", buffer);
        }
        switch (*instanceState)
        {
        case start:
            if (strncmp(buffer, "INIT", 4) == 0)
            {
                reply_and_update(socketConnection, instanceState, "ACK\n", inited);
                if (debug)
                {
                    printf("Process %d: STATE: start ->init\n", pid);
                }
            }
            else
            {
                send(socketConnection, "ERROR\n", strlen("ERROR\n"), 0);
                if (debug)
                {
                    printf("Process %d: STATE: start -> start\n", pid);
                }
            }
            break;
        case inited:
            if (strncmp(buffer, "AUTH", 4) == 0)
            {
                reply_and_update(socketConnection, instanceState, "ACK\n", authed);
                if (debug)
                {
                    printf("Process %d: STATE: inited -> authed\n", pid);
                }
            }
            else if (strncmp(buffer, "INIT", 4) == 0)
            {
                send(socketConnection, "ACK\n", strlen("ACK\n"), 0);
                if (debug)
                {
                    printf("Process %d: STATE: inited -> inited\n", pid);
                }
            }
            else
            {
                reply_and_update(socketConnection, instanceState, "ERROR\n", error);
                if (debug)
                {
                    printf("Process %d: STATE: inited -> error\n", pid);
                }
            }
            break;
        case authed:
            if (strncmp(buffer, "DATA", 4) == 0 || strncmp(buffer, "AUTH", 4) == 0)
            {
                reply_and_update(socketConnection, instanceState, "ACK\n", authed);
                if (debug)
                {
                    printf("Process %d: STATE: authed -> authed\n", pid);
                }
            }
            else if (strncmp(buffer, "CLOSE", 5) == 0)
            {
                if (debug)
                {
                    printf("Ending process %d\n", pid);
                }
                shutdown(socketConnection, SHUT_RDWR);
                close(socketConnection);
                exit(EXIT_SUCCESS);
            }
            else
            {
                reply_and_update(socketConnection, instanceState, "ERROR\n", error);
                if (debug)
                {
                    printf("Process %d: STATE: authed -> error\n", pid);
                }
            }
            break;
        case error:
            if (strncmp(buffer, "CLOSE", 5) == 0)
            {
                if (debug)
                {
                    printf("Ending process %d\n", pid);
                }
                *instanceState = closed;
                shutdown(socketConnection, SHUT_RDWR);
                close(socketConnection);
                exit(EXIT_SUCCESS);
            }
            else
            {
                send(socketConnection, "ERROR\n", strlen("ERROR\n"), 0);
                if (debug)
                {
                    printf("Process %d: STATE: error -> error\n", pid);
                }
            }
            break;
        }
    }
    close(socketConnection);
    exit(EXIT_SUCCESS);
}

int main()
{
    std::cout << "Hello world!" << std::endl;

    struct sockaddr_in address;
    int addrlen = sizeof(address);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        printf("ERROR opening socket");
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
               &opt, sizeof(opt));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&address,
             sizeof(address)) < 0)
    {
        printf("bind failed");
        exit(EXIT_FAILURE);
    }
    std::cout << "Openning socket" << std::endl;

    if (listen(sockfd, 3) < 0)
    {
        printf("error listenning");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        int new_socket;
        std::cout << "Listening" << std::endl;

        if ((new_socket = accept(sockfd, (struct sockaddr *)&address,
                                 (socklen_t *)&addrlen)) < 0)
        {
            exit(EXIT_FAILURE);
        }
        std::cout << "Got connection" << std::endl;
        int pid_c = fork();
        if (pid_c == 0)
        {
            protocolInstance(new_socket);
        }
        else if (pid_c > 0)
        {
            pid_t w = -1;
            int status = 0;
            while ((w = waitpid(-1, &status, WNOHANG)) > 0)
                ;
        }
    }
}
