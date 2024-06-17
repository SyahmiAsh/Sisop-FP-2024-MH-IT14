#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

void send_command(int socket, const char *command) {
    send(socket, command, strlen(command), 0);
    char buffer[BUFFER_SIZE];
    int bytes_read = read(socket, buffer, BUFFER_SIZE);
    buffer[bytes_read] = '\0';
    printf("Server response: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <REGISTER|LOGIN> <username> -p <password>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int client_socket;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // Send initial command (REGISTER or LOGIN)
    char initial_command[BUFFER_SIZE];
    snprintf(initial_command, BUFFER_SIZE, "%s %s -p %s", argv[1], argv[2], argv[4]);
    send_command(client_socket, initial_command);

    while (1) {
        printf("Enter command: ");
        if (fgets(buffer, BUFFER_SIZE, stdin) == NULL) {
            break;
        }
        buffer[strcspn(buffer, "\n")] = '\0'; // Remove newline character

        if (strcmp(buffer, "EXIT") == 0) {
            break;
        }

        send_command(client_socket, buffer);
    }

    close(client_socket);
    return 0;
}
