#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

void send_command(int socket, const char *command, char *response) {
    send(socket, command, strlen(command), 0);
    int bytes_read = read(socket, response, BUFFER_SIZE);
    response[bytes_read] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <REGISTER|LOGIN> <username> -p <password>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int client_socket;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];

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
    send_command(client_socket, initial_command, response);
    printf("Server response: %s\n", response);

    // Check if login was successful
    if (strncmp(response + strlen(argv[2]), " berhasil login", 15) == 0) {
        printf("[%s] ", argv[2]);
        while (1) {
            if (fgets(buffer, BUFFER_SIZE, stdin) == NULL) {
                break;
            }
            buffer[strcspn(buffer, "\n")] = '\0'; // Remove newline character

            if (strcmp(buffer, "EXIT") == 0) {
                break;
            }

            send_command(client_socket, buffer, response);
            printf("Server response: %s\n", response);

            // Check if the command was EDIT PROFILE SELF -u and update the prompt username if successful
            if (strncmp(buffer, "EDIT PROFILE SELF -u ", 21) == 0 && strstr(response, "Profil diupdate") != NULL) {
                char *new_username = buffer + 21;
                strncpy(argv[2], new_username, BUFFER_SIZE); // Update the username
            }

            printf("[%s] ", argv[2]); // Use updated username
        }
    }

    close(client_socket);
    return 0;
}
