#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define PORT 8080

int login = 0;

void error(const char *msg) {
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char buffer[256];

    if (argc < 4) {
        fprintf(stderr, "usage: %s command username password\n", argv[0]);
        exit(0);
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    server = gethostbyname("localhost");
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(PORT);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
        error("ERROR connecting");

    if (strcmp(argv[1], "CREATE") == 0 && strcmp(argv[2], "CHANNEL") == 0) {
        if (argc < 6) {
            fprintf(stderr, "usage for create channel: %s CREATE CHANNEL channel_name -k key\n", argv[0]);
            exit(0);
        }
        sprintf(buffer, "%s %s %s -k %s", argv[1], argv[2], argv[3], argv[5]);
    } else {
        sprintf(buffer, "%s %s -p %s", argv[1], argv[2], argv[3]);
    }

    write(sockfd, buffer, strlen(buffer));

    bzero(buffer, 256);
    ssize_t n = read(sockfd, buffer, 255);
    if (n < 0) 
        error("ERROR reading from socket");
    
    printf("%s\n", buffer);
    if (strncmp("berhasil", buffer, 8) == 0) {
        login = 1;
    }

    if (login) {
        while (1) {
            printf("[%s] ", argv[2]);
            bzero(buffer, 256);
            fgets(buffer, 255, stdin);

            write(sockfd, buffer, strlen(buffer));
            if (strncmp("exit", buffer, 4) == 0) {
                printf("Client Exit...\n");
                break;
            }

            bzero(buffer, 256);
            n = read(sockfd, buffer, 255);
            if (n < 0) 
                error("ERROR reading from socket");
            
            printf("%s\n", buffer);
        }
    }

    close(sockfd);
    return 0;
}
