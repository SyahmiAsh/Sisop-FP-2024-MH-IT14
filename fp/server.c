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
#include <signal.h> // Tambahkan header signal.h
#include <bcrypt.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define FILE_PATH "/home/kali/Documents/fp/DiscorIT/users.csv"

void handle_client(int client_socket);
void daemonize();
void ensure_user_file_exists();
bool register_user(const char *username, const char *password, char *response);
bool login_user(const char *username, const char *password, char *response, char *role);
void list_users(int client_socket);
bool edit_user(const char *username, const char *new_username, const char *new_password, char *response);
bool remove_user(const char *username, char *response);
bool edit_profile_self(const char *current_username, const char *new_username, const char *new_password, char *response);

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

    char current_username[BUFFER_SIZE] = {0};
    char current_role[BUFFER_SIZE] = {0};
    bool is_logged_in = false;

    while ((bytes_read = read(client_socket, buffer, BUFFER_SIZE)) > 0) {
        buffer[bytes_read] = '\0';
        printf("Received from client: %s\n", buffer);

        char response[BUFFER_SIZE] = {0};

        char *command = strtok(buffer, " ");
        printf("Debug: Command received: %s\n", command); // Debug statement

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
            if (login_user(username, password, response, current_role)) {
                snprintf(response, BUFFER_SIZE, "%s berhasil login", username);
                strncpy(current_username, username, BUFFER_SIZE);
                is_logged_in = true;
            } else {
                snprintf(response, BUFFER_SIZE, "username atau password salah");
            }
        } else if (strcmp(command, "LIST") == 0) {
            char *sub_command = strtok(NULL, " ");
            if (sub_command != NULL && strcmp(sub_command, "USER") == 0) {
                if (is_logged_in && strcmp(current_role, "ROOT") == 0) {
                    list_users(client_socket);
                } else {
                    snprintf(response, BUFFER_SIZE, "Permission denied");
                }
                continue; // Skip the default response write below
            } else {
                snprintf(response, BUFFER_SIZE, "Unknown sub-command: %s", sub_command);
            }
        } else if (strcmp(command, "EDIT") == 0) {
            char *sub_command = strtok(NULL, " ");
            if (strcmp(sub_command, "WHERE") == 0) {
                if (is_logged_in && strcmp(current_role, "ROOT") == 0) {
                    char *username = strtok(NULL, " ");
                    char *option = strtok(NULL, " ");
                    if (strcmp(option, "-u") == 0) {
                        char *new_username = strtok(NULL, " ");
                        if (edit_user(username, new_username, NULL, response)) {
                            snprintf(response, BUFFER_SIZE, "user %s berhasil diubah menjadi %s", username, new_username);
                        }
                    } else if (strcmp(option, "-p") == 0) {
                        char *new_password = strtok(NULL, " ");
                        if (edit_user(username, NULL, new_password, response)) {
                            snprintf(response, BUFFER_SIZE, "password user %s berhasil diubah", username);
                        }
                    }
                } else {
                    snprintf(response, BUFFER_SIZE, "Permission denied");
                }
            } else if (strcmp(sub_command, "PROFILE") == 0 && is_logged_in) {
                char *profile_command = strtok(NULL, " ");
                if (strcmp(profile_command, "SELF") == 0) {
                    char *option = strtok(NULL, " ");
                    if (strcmp(option, "-u") == 0) {
                        char *new_username = strtok(NULL, " ");
                        if (edit_profile_self(current_username, new_username, NULL, response)) {
                            snprintf(response, BUFFER_SIZE, "Profil diupdate\n%s", new_username);
                            strncpy(current_username, new_username, BUFFER_SIZE);
                        }
                    } else if (strcmp(option, "-p") == 0) {
                        char *new_password = strtok(NULL, " ");
                        if (edit_profile_self(current_username, NULL, new_password, response)) {
                            snprintf(response, BUFFER_SIZE, "Password diupdate");
                        }
                    }
                }
            } else {
                snprintf(response, BUFFER_SIZE, "Unknown sub-command: %s", sub_command);
            }
        } else if (strcmp(command, "REMOVE") == 0) {
            if (is_logged_in && strcmp(current_role, "ROOT") == 0) {
                char *username = strtok(NULL, " ");
                if (remove_user(username, response)) {
                    snprintf(response, BUFFER_SIZE, "user %s berhasil dihapus", username);
                }
            } else {
                snprintf(response, BUFFER_SIZE, "Permission denied");
            }
        } else {
            snprintf(response, BUFFER_SIZE, "Unknown command: %s", command);
        }

        printf("Debug: Sending response: %s\n", response); // Debug statement
        write(client_socket, response, strlen(response));
    }

    close(client_socket);
}


void list_users(int client_socket) {
    FILE *file = fopen(FILE_PATH, "r");
    if (file == NULL) {
        perror("Failed to open file");
        return;
    }

    char line[BUFFER_SIZE];
    char response[BUFFER_SIZE] = {0};

    while (fgets(line, sizeof(line), file)) {
        char username[BUFFER_SIZE];
        sscanf(line, "%*d,%[^,],%*[^,],%*s", username);
        strcat(response, username);
        strcat(response, " ");
    }

    fclose(file);
    write(client_socket, response, strlen(response));
}

bool edit_user(const char *username, const char *new_username, const char *new_password, char *response) {
    FILE *file = fopen(FILE_PATH, "r+");
    if (file == NULL) {
        perror("Failed to open file");
        return false;
    }

    char line[BUFFER_SIZE];
    char temp_path[] = "/tmp/temp_users.csv";
    FILE *temp_file = fopen(temp_path, "w");
    if (temp_file == NULL) {
        perror("Failed to open temp file");
        fclose(file);
        return false;
    }

    bool user_found = false;
    while (fgets(line, sizeof(line), file)) {
        char file_username[BUFFER_SIZE], file_password[BCRYPT_HASHSIZE], role[BUFFER_SIZE];
        int id;
        sscanf(line, "%d,%[^,],%[^,],%s", &id, file_username, file_password, role);

        if (strcmp(file_username, username) == 0) {
            user_found = true;
            if (new_username != NULL) {
                fprintf(temp_file, "%d,%s,%s,%s\n", id, new_username, file_password, role);
            } else if (new_password != NULL) {
                char salt[BCRYPT_HASHSIZE];
                char encrypted_password[BCRYPT_HASHSIZE];

                if (bcrypt_gensalt(12, salt) != 0) {
                    perror("Error generating salt");
                    fclose(file);
                    fclose(temp_file);
                    return false;
                }
                if (bcrypt_hashpw(new_password, salt, encrypted_password) != 0) {
                    perror("Error hashing password");
                    fclose(file);
                    fclose(temp_file);
                    return false;
                }
                fprintf(temp_file, "%d,%s,%s,%s\n", id, file_username, encrypted_password, role);
            }
        } else {
            fprintf(temp_file, "%s", line);
        }
    }

    fclose(file);
    fclose(temp_file);

    if (user_found) {
        remove(FILE_PATH);
        rename(temp_path, FILE_PATH);
    } else {
        remove(temp_path);
        snprintf(response, BUFFER_SIZE, "user %s tidak ditemukan", username);
    }

    return user_found;
}

bool remove_user(const char *username, char *response) {
    FILE *file = fopen(FILE_PATH, "r");
    if (file == NULL) {
        perror("Failed to open file");
        return false;
    }

    char line[BUFFER_SIZE];
    char temp_path[] = "/tmp/temp_users.csv";
    FILE *temp_file = fopen(temp_path, "w");
    if (temp_file == NULL) {
        perror("Failed to open temp file");
        fclose(file);
        return false;
    }

    bool user_found = false;
    while (fgets(line, sizeof(line), file)) {
        char file_username[BUFFER_SIZE];
        sscanf(line, "%*d,%[^,],%*[^,],%*s", file_username);

        if (strcmp(file_username, username) == 0) {
            user_found = true;
            continue;
        }

        fprintf(temp_file, "%s", line);
    }

    fclose(file);
    fclose(temp_file);

    if (user_found) {
        remove(FILE_PATH);
        rename(temp_path, FILE_PATH);
    } else {
        remove(temp_path);
        snprintf(response, BUFFER_SIZE, "user %s tidak ditemukan", username);
    }

    return user_found;
}

bool edit_profile_self(const char *current_username, const char *new_username, const char *new_password, char *response) {
    return edit_user(current_username, new_username, new_password, response);
}

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    umask(0);
    chdir("/");
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }
}

void ensure_user_file_exists() {
    int fd = open(FILE_PATH, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        perror("Failed to create file");
        exit(EXIT_FAILURE);
    }
    close(fd);
}

bool register_user(const char *username, const char *password, char *response) {
    FILE *file = fopen(FILE_PATH, "a+");
    if (file == NULL) {
        perror("Failed to open file");
        return false;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file)) {
        char existing_username[BUFFER_SIZE];
        sscanf(line, "%*d,%[^,],%*[^,],%*s", existing_username);

        if (strcmp(existing_username, username) == 0) {
            snprintf(response, BUFFER_SIZE, "Username sudah terdaftar");
            fclose(file);
            return false;
        }
    }

    char salt[BCRYPT_HASHSIZE];
    char encrypted_password[BCRYPT_HASHSIZE];

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

    int id = 1;
    if (ftell(file) > 0) {
        fseek(file, -BUFFER_SIZE, SEEK_END);
        fgets(line, sizeof(line), file);
        sscanf(line, "%d,", &id);
        id++;
    }

    fprintf(file, "%d,%s,%s,USER\n", id, username, encrypted_password);
    fclose(file);
    return true;
}

bool login_user(const char *username, const char *password, char *response, char *role) {
    FILE *file = fopen(FILE_PATH, "r");
    if (file == NULL) {
        perror("Failed to open file");
        return false;
    }

    char line[BUFFER_SIZE];
    bool login_successful = false;
    while (fgets(line, sizeof(line), file)) {
        char file_username[BUFFER_SIZE], file_password[BCRYPT_HASHSIZE], file_role[BUFFER_SIZE];
        sscanf(line, "%*d,%[^,],%[^,],%s", file_username, file_password, file_role);

        if (strcmp(file_username, username) == 0) {
            if (bcrypt_checkpw(password, file_password) == 0) {
                login_successful = true;
                strncpy(role, file_role, BUFFER_SIZE);
                snprintf(response, BUFFER_SIZE, "%s berhasil login", username);
                break;
            } else {
                login_successful = false;
            }
        }
    }

    fclose(file);
    return login_successful;
}
