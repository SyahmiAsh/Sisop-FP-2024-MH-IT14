#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <errno.h>
#include <bcrypt.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define FILE_PATH "/home/kali/Documents/fp/DiscorIT/users.csv"

void handle_client(int client_socket);
void daemonize();
void ensure_user_file_exists();
bool register_user(const char *username, const char *password, char *response);
bool login_user(const char *username, const char *password, char *response);

int main() {
    ensure_user_file_exists();
    
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    daemonize();

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 3) < 0) {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    while ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len)) >= 0) {
        if (fork() == 0) {
            close(server_socket);
            handle_client(client_socket);
            exit(0);
        }
        close(client_socket);
    }

    close(server_socket);
    return 0;
}

void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = read(client_socket, buffer, BUFFER_SIZE)) > 0) {
        buffer[bytes_read] = '\0';
        printf("Received from client: %s\n", buffer);

        char response[BUFFER_SIZE] = {0};

        char *command = strtok(buffer, " ");
        if (strcmp(command, "REGISTER") == 0) {
            char *username = strtok(NULL, " ");
            strtok(NULL, " "); // Skip -p
            char *password = strtok(NULL, " ");
            if (register_user(username, password, response)) {
                snprintf(response, BUFFER_SIZE, "%s berhasil register", username);
            }
        } else if (strcmp(command, "LOGIN") == 0) {
            char *username = strtok(NULL, " ");
            strtok(NULL, " "); // Skip -p
            char *password = strtok(NULL, " ");
            bool login_success = login_user(username, password, response);
            printf("Debug: login_user returned %d\n", login_success); // Debug statement
            if (login_success) {
                snprintf(response, BUFFER_SIZE, "%s berhasil login", username);
            } else {
                snprintf(response, BUFFER_SIZE, "username atau password salah"); // Add a generic error message for login failure
            }
        } else {
            snprintf(response, BUFFER_SIZE, "Unknown command: %s", command);
        }

        printf("Debug: Sending response: %s\n", response); // Debug statement
        write(client_socket, response, strlen(response));
    }

    close(client_socket);
}


void daemonize() {
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    if (setsid() < 0) {
        perror("setsid failed");
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid < 0) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(027);
    if (chdir("/") < 0) {
        perror("chdir failed");
        exit(EXIT_FAILURE);
    }

    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }

    open("/dev/null", O_RDONLY);
    open("/dev/null", O_RDWR);
    open("/dev/null", O_RDWR);

    // Redirect stdout and stderr to debug.txt
    freopen("/home/kali/Documents/fp/debug.txt", "a+", stdout);
    freopen("/home/kali/Documents/fp/debug.txt", "a+", stderr);
}


void ensure_user_file_exists() {
    FILE *file = fopen(FILE_PATH, "a");
    if (file == NULL) {
        perror("Failed to open or create file");
        exit(EXIT_FAILURE);
    }
    fclose(file);
}

bool register_user(const char *username, const char *password, char *response) {
    FILE *file = fopen(FILE_PATH, "r+");
    if (file == NULL) {
        perror("Failed to open file");
        return false;
    }

    char line[BUFFER_SIZE];
    int id_user = 1;
    bool user_exists = false;

    while (fgets(line, sizeof(line), file)) {
        char file_username[BUFFER_SIZE];
        sscanf(line, "%*d,%[^,],%*[^,],%*s", file_username);
        if (strcmp(file_username, username) == 0) {
            snprintf(response, BUFFER_SIZE, "username sudah terdaftar");
            user_exists = true;
            break;
        }
        id_user++;
    }

    if (!user_exists) {
        char salt[BCRYPT_HASHSIZE];
        char encrypted_password[BCRYPT_HASHSIZE];

        // Generate salt and hash the password
        if (bcrypt_gensalt(12, salt) != 0) {
            perror("Error generating salt");
            fclose(file);
            return false;
        }
        if (bcrypt_hashpw(password, salt, encrypted_password) != 0) {
            perror("Error hashing password");
            fclose(file);
            return false;
        }

        const char *global_role = (id_user == 1) ? "ROOT" : "USER";
        fprintf(file, "%d,%s,%s,%s\n", id_user, username, encrypted_password, global_role);
        snprintf(response, BUFFER_SIZE, "%s berhasil register", username);
    }

    fclose(file);
    return !user_exists;
}

bool login_user(const char *username, const char *password, char *response) {
    FILE *file = fopen(FILE_PATH, "r");
    if (file == NULL) {
        perror("Failed to open file");
        return false;
    }

    char line[BUFFER_SIZE];
    bool user_found = false;

    while (fgets(line, sizeof(line), file)) {
        char file_username[BUFFER_SIZE], file_password[BCRYPT_HASHSIZE];
        sscanf(line, "%*d,%[^,],%[^,],%*s", file_username, file_password);
        if (strcmp(file_username, username) == 0) {
            user_found = true;
            printf("Debug: Found user %s in file\n", file_username); // Debug statement

            printf("Debug: Provided password: %s\n", password); // Debug statement
            printf("Debug: Stored hashed password: %s\n", file_password); // Debug statement

            if (bcrypt_checkpw(password, file_password) == 0) {
                snprintf(response, BUFFER_SIZE, "%s berhasil login", username);
                printf("Debug: Password match for user %s\n", username); // Debug statement
                fclose(file);
                return true;  // Ensure to return true on successful login
            } else {
                snprintf(response, BUFFER_SIZE, "password salah");
                printf("Debug: Password mismatch for user %s\n", username); // Debug statement
                fclose(file);
                return false;  // Ensure to return false on password mismatch
            }
        }
    }

    if (!user_found) {
        snprintf(response, BUFFER_SIZE, "user tidak ditemukan");
        printf("Debug: User %s not found\n", username); // Debug statement
    }

    fclose(file);
    return user_found;
}

