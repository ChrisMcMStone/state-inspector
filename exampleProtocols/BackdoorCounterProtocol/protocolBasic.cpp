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

enum State {
    start,
    inited,
    authed,
    error
};
// The tool terminates quite happily with an infinite counter in the data section of the memory
// int messageCounter = 0;   // This counter is new in this file
int debug = 1;

void protocolInstance(int socketConnection)
{
    printf("protocol instance started\n");

    State *instanceState;
    instanceState = (State *)malloc(sizeof(State));
    *instanceState = start;

    // We force the message counter onto the heap
    int *messageCounter;
    messageCounter = (int *)malloc(sizeof(int));

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
                    send(socketConnection, "ACK\n", strlen("ACK\n"), 0);
                    *instanceState = inited;
                }
                else
                {
                    send(socketConnection, "ERROR\n", strlen("ERROR\n"), 0);
                }
                break;
            case inited:
                ++(*messageCounter); // I change the state of the counter but don't use it.
                if (strncmp(buffer, "AUTH", 4) == 0)
                {
                    send(socketConnection, "ACK\n", strlen("ACK\n"), 0);
                    *instanceState = authed;
                } 
                else if (*messageCounter > 9) {
                    send(socketConnection, "ACK\n", strlen("ACK\n"), 0);
                    *instanceState = authed;
                }
                else if (strncmp(buffer, "INIT", 4) == 0)
                {
                    send(socketConnection, "ACK\n", strlen("ACK\n"), 0);
                }
                else
                {
                    send(socketConnection, "ERROR\n", strlen("ERROR\n"), 0);
                    *instanceState = error;
                }
                break;
            case authed:
                if (strncmp(buffer, "DATA", 4) == 0 || strncmp(buffer, "AUTH", 4) == 0)
                {
                    send(socketConnection, "ACK\n", strlen("ACK\n"), 0);
                    *instanceState = authed;
                }
                else if (strncmp(buffer, "CLOSE", 5) == 0)
                {
                    shutdown(socketConnection, SHUT_RDWR);
                    close(socketConnection);
                    break;
                }
                else
                {
                    send(socketConnection, "ERROR\n", strlen("ERROR\n"), 0);
                    *instanceState = error;
                }
                break;
            case error:
                if (strncmp(buffer, "CLOSE", 5) == 0)
                {
                    shutdown(socketConnection, SHUT_RDWR);
                    close(socketConnection);
                    break;
                }
                else
                {
                    send(socketConnection, "ERROR\n", strlen("ERROR\n"), 0);
                }
                break;
            }
    }
    free(instanceState);
    free(messageCounter);
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

    int new_socket;
    std::cout << "Listening" << std::endl;

    while(1) {
        new_socket = accept(sockfd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        if(new_socket < 0) {
            std::cout << "accept failed" << std::endl;
            exit(1);
        }
        protocolInstance(new_socket);
        close(new_socket);
    }
}
