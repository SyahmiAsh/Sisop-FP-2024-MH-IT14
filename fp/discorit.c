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
char username[50];
char channel[50] = "";
char room[50] = "";
#define BUF_SIZE 256

void error(const char *msg) {
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char buffer[BUF_SIZE];

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

    if (argc == 3) { 
        sprintf(buffer, "%s %s", argv[1], argv[2]);
    } else if (argc == 4) { 
        sprintf(buffer, "%s %s %s", argv[1], argv[2], argv[3]);
    } else if (argc == 5) {
        sprintf(buffer, "%s %s %s %s", argv[1], argv[2], argv[3], argv[4]);
    } else if (argc == 6) {
        sprintf(buffer, "%s %s %s %s %s", argv[1], argv[2], argv[3], argv[4], argv[5]);
    }

    write(sockfd, buffer, strlen(buffer));

    bzero(buffer, BUF_SIZE);
    ssize_t n = read(sockfd, buffer, BUF_SIZE - 1);
    if (n < 0) 
        error("ERROR reading from socket");
    
    printf("%s\n", buffer);
    if (strncmp("berhasil", buffer, 8) == 0) {
        login = 1;
    }

    if (login) {
        strcpy(username, argv[2]);
        while (1) {
            if (strlen(channel) > 0) {
                printf("[%s/%s] ", username, channel);
            } else {
                printf("[%s] ", username);
            }

            bzero(buffer, BUF_SIZE);
            fgets(buffer, BUF_SIZE - 1, stdin);

            // Handle JOIN command
            if (strncmp("JOIN", buffer, 4) == 0) {
                char *channel_name = strtok(buffer + 5, " \n");
                if (channel_name) {
                    sprintf(buffer, "JOIN %s", channel_name);
                    write(sockfd, buffer, strlen(buffer));
                    bzero(buffer, BUF_SIZE);
                    n = read(sockfd, buffer, BUF_SIZE - 1);
                    if (n < 0) 
                        error("ERROR reading from socket");
                    printf("%s\n", buffer);
                    if (strstr(buffer, "User") != NULL && strstr(buffer, "joined channel") != NULL) {
                        // Extract channel name from the response
                        sscanf(buffer, "User '%*[^']' joined channel '%49[^']'", channel);
                    }
                    continue; // Skip the rest of the loop
                }
            } 
            // Handle EXIT command
            else if (strcmp("EXIT\n", buffer) == 0) {
                if (strlen(channel) > 0) {
                    channel[0] = '\0';
                }
            } 
            // Handle CREATE ROOM command
            else if (strncmp("CREATE ROOM", buffer, 11) == 0) {
                if (strlen(channel) == 0) {
                    printf("You need to join a channel first\n");
                    continue;
                }
                char *room_name = strtok(buffer + 12, " \n");

                // Print the extracted room_name for debugging
                printf("Extracted room_name: %s\n", room_name);
                printf("chanel_name: %s\n", channel);

                if (room_name) {

                     char command[BUF_SIZE];
                    strcpy(command, "CREATE ROOM ");
                    strcat(command, channel);
                    strcat(command, " ");
                    strcat(command, room_name);
                    snprintf(buffer, BUF_SIZE, "%s", command);
                    // Print the constructed message for debugging
                    printf("Constructed message: %s\n", buffer);

                    write(sockfd, buffer, strlen(buffer));
                    bzero(buffer, BUF_SIZE);
                    n = read(sockfd, buffer, BUF_SIZE - 1);
                    if (n < 0) 
                        error("ERROR reading from socket");
                    printf("%s\n", buffer);
                    continue; // Skip the rest of the loop
                } else {
                    printf("Usage: CREATE ROOM <room_name>\n");
                    continue;
                }
            }

            write(sockfd, buffer, strlen(buffer));
            if (strncmp("exit", buffer, 4) == 0) {
                printf("Client Exit...\n");
                break;
            }

            bzero(buffer, BUF_SIZE);
            n = read(sockfd, buffer, BUF_SIZE - 1);
            if (n < 0) 
                error("ERROR reading from socket");
            
            printf("%s\n", buffer);
            if (strstr(buffer, "User") != NULL && strstr(buffer, "joined channel") != NULL) {
                // Extract channel name from the response
                sscanf(buffer, "User '%*[^']' joined channel '%49[^']'", channel);
            }
        }
    }

    close(sockfd);
    return 0;
}
