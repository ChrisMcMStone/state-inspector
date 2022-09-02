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

enum State { start, inited, authed, error };
// The tool terminates quite happily with an infinite counter in the data section of the memory
// int messageCounter = 0;   // This counter is new in this file    
int debug = 1;

void protocolInstance(int socketConnection)
{
    
    pid_t pid = getpid();
    
    State *instanceState;
    instanceState =(State*)malloc(sizeof(State));
    *instanceState = start;

    int *messageCounter;
    messageCounter =(int*)malloc(sizeof(int));

    std::cout << std::hex << instanceState << std::dec << std::endl;
    
    char buffer[1024] = {0}; 
    while(read( socketConnection , buffer, 1024)>0) {
        ++(*messageCounter);    // I change the state of the counter but don't use it.
        if (debug) {  printf("Got: %s",buffer); }
        switch( *instanceState ) {
            case start:
                if (strncmp(buffer,"INIT",4)==0) {
                    send(socketConnection , "ACK\n" , strlen("ACK\n") , 0 ); 
                    *instanceState = inited;
                    if (debug) {printf("Process %d (%d): STATE: start ->init\n", pid, *messageCounter); }
                } else { 
                    send(socketConnection , "ERROR\n" , strlen("ERROR\n") , 0 ); 
                     if (debug) {printf("Process %d (%d): STATE: start -> start\n", pid, *messageCounter); }

                }
            break;
            case inited:
              if (strncmp(buffer,"AUTH",4)==0) {
                    send(socketConnection , "ACK\n" , strlen("ACK\n") , 0 ); 
                    *instanceState = authed;
		    if (debug) {printf("Process %d (%d): STATE: inited -> authed\n", pid, *messageCounter);}
                } else if (strncmp(buffer,"INIT",4)==0) {
                    send(socketConnection , "ACK\n" , strlen("ACK\n") , 0 );
		    if (debug) {printf("Process %d (%d): STATE: inited -> inited\n", pid, *messageCounter);}
                } else { 
                    send(socketConnection , "ERROR\n" , strlen("ERROR\n") , 0 ); 
                    *instanceState = error;
		    if (debug) {printf("Process %d (%d): STATE: inited -> error\n", pid, *messageCounter);}
                }
            break;
            case authed:
            if (strncmp(buffer,"DATA",4)==0 || strncmp(buffer,"AUTH",4)==0) {
                    send(socketConnection , "ACK\n" , strlen("ACK\n") , 0 ); 
                    *instanceState = authed;
		    if (debug) {printf("Process %d (%d): STATE: authed -> authed\n", pid, *messageCounter);}
                } else if (strncmp(buffer,"CLOSE",5)==0) {
		     if (debug) {printf("Ending Process %d (%d)\n", pid, *messageCounter);}
		     shutdown(socketConnection, SHUT_RDWR);
		     close(socketConnection);
                     exit(EXIT_SUCCESS);
                } else { 
                    send(socketConnection , "ERROR\n" , strlen("ERROR\n") , 0 ); 
                    *instanceState = error;
		    if (debug) {printf("Process %d (%d): STATE: authed -> error\n", pid, *messageCounter);}
                }
            break;            
            case error:
                if (strncmp(buffer,"CLOSE",5)==0) {
		    if (debug) {printf("Ending Process %d (%d)\n", pid, *messageCounter);}
		    shutdown(socketConnection, SHUT_RDWR);
		    close(socketConnection);
                    exit(EXIT_SUCCESS);
                } else {
                    send(socketConnection , "ERROR\n" , strlen("ERROR\n") , 0 );
		    if (debug) {printf("Process %d (%d): STATE: error -> error\n", pid, *messageCounter);}
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
    address.sin_port = htons( PORT ); 

    if (bind(sockfd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
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

    while (1) {
        int new_socket;
            std::cout << "Listening" << std::endl;

        if ((new_socket = accept(sockfd, (struct sockaddr *)&address,  
                       (socklen_t*)&addrlen))<0) 
        { 
            exit(EXIT_FAILURE); 
        } 
        std::cout << "Got connection" << std::endl;
        int pid_c = fork();
        if (pid_c==0) {
            protocolInstance(new_socket);
        } else if (pid_c > 0) {
            pid_t w = -1;
	    int status = 0;
            while ((w = waitpid(-1, &status, WNOHANG)) > 0);
	}
    }
}
