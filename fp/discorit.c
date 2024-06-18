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

void connect_to_server(int *client_socket, struct sockaddr_in *server_addr) {
    *client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (*client_socket == -1) {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }

    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(PORT);
    server_addr->sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(*client_socket, (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
        perror("Connection failed");
        close(*client_socket);
        exit(EXIT_FAILURE);
    }
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
    char prompt[BUFFER_SIZE];
    char current_channel[BUFFER_SIZE] = "";

    // Connect to the server
    connect_to_server(&client_socket, &server_addr);

    // Send initial command (REGISTER or LOGIN)
    snprintf(buffer, BUFFER_SIZE, "%s %s -p %s", argv[1], argv[2], argv[4]);
    send_command(client_socket, buffer, response);
    printf("%s\n", response);

    if (strstr(response, "berhasil login") != NULL) {
        snprintf(prompt, BUFFER_SIZE, "[%s] ", argv[2]);
        printf("%s", prompt);

        while (1) {
            if (fgets(buffer, BUFFER_SIZE, stdin) == NULL) {
                break;
            }
            buffer[strcspn(buffer, "\n")] = '\0'; // Remove newline character

            // Handle different commands
            if (strcmp(buffer, "EXIT") == 0) {
                break;
            } else if (strncmp(buffer, "JOIN ", 5) == 0) {
                char channel_name[BUFFER_SIZE];
                sscanf(buffer, "JOIN %s", channel_name);

                // Send JOIN command
                send_command(client_socket, buffer, response);

                // If key is required, prompt for it
                if (strstr(response, "Key:") != NULL) {
                    printf("Key: ");
                    if (fgets(buffer, BUFFER_SIZE, stdin) == NULL) {
                        break;
                    }
                    buffer[strcspn(buffer, "\n")] = '\0'; // Remove newline character
                    char key_command[BUFFER_SIZE];
                    snprintf(key_command, BUFFER_SIZE, "JOIN %s -k %s", channel_name, buffer);
                    send_command(client_socket, key_command, response);
                }
                // Update prompt
                snprintf(current_channel, BUFFER_SIZE, "%s", channel_name);
                snprintf(prompt, BUFFER_SIZE, "[%s/%s] ", argv[2], channel_name);
                printf("%s\n%s", response, prompt);
                continue;
            } else if (strncmp(buffer, "CREATE CHANNEL ", 15) == 0) {
                // Send CREATE CHANNEL command
                send_command(client_socket, buffer, response);
                printf("%s\n%s", response, prompt);
                continue;
            } else if (strncmp(buffer, "LIST CHANNEL", 12) == 0) {
                // Send LIST CHANNEL command
                send_command(client_socket, buffer, response);
                printf("%s\n%s", response, prompt);
                continue;
            } else if (strncmp(buffer, "LIST USER", 9) == 0) {
                // Send LIST USER command
                send_command(client_socket, buffer, response);
                printf("%s\n%s", response, prompt);
                continue;
            } else if (strncmp(buffer, "EDIT PROFILE SELF -u ", 21) == 0) {
                // Handle EDIT PROFILE SELF -u command
                send_command(client_socket, buffer, response);
                printf("%s\n", response);
                if (strstr(response, "Profil diupdate") != NULL) {
                    char *new_username = buffer + 21;
                    argv[2] = strdup(new_username); // Allocate new memory for the updated username
                    snprintf(prompt, BUFFER_SIZE, "[%s] ", new_username);
                }
                printf("%s", prompt); // Use updated prompt
                continue;
            }

            // Send other commands
            send_command(client_socket, buffer, response);
            printf("%s\n%s", response, prompt); // Print response and prompt
        }
    }

    close(client_socket);
    return 0;
}
