#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

void monitor_chat(int sock, char *channel, char *room);

int main(int argc, char const *argv[]) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    printf("Connected to the server\n");

    // Example monitoring command
    monitor_chat(sock, "care", "urban");

    return 0;
}

void monitor_chat(int sock, char *channel, char *room) {
    char command[BUFFER_SIZE];
    snprintf(command, BUFFER_SIZE, "%s -channel %s -room %s", "qurbancare", channel, room);
    send(sock, command, strlen(command), 0);
    printf("Sent: %s\n", command);

    char response[BUFFER_SIZE];
    while (read(sock, response, BUFFER_SIZE) > 0) {
        printf("Chat: %s\n", response);
    }
}
