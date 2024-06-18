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
#include <signal.h>
#include <bcrypt.h>
#include <time.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define FILE_PATH "/home/kali/Documents/fp/DiscorIT/users.csv"
#define CHANNELS_PATH "/home/kali/Documents/fp/DiscorIT/channels.csv"
#define BASE_PATH "/home/kali/Documents/fp/DiscorIT"

void handle_client(int client_socket);
void daemonize();
void ensure_files_exist();
bool register_user(const char *username, const char *password, char *response);
bool login_user(const char *username, const char *password, char *response, char *role);
void list_users(int client_socket);
bool edit_user(const char *username, const char *new_username, const char *new_password, char *response);
bool remove_user(const char *username, char *response);
bool edit_profile_self(const char *current_username, const char *new_username, const char *new_password, char *response);
bool create_channel(const char *channel, const char *key, const char *username, char *response);
void list_channels(int client_socket);
bool join_channel(const char *username, const char *channel, const char *key, char *response, char *role);

int main() {
    ensure_files_exist();

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
    char current_channel[BUFFER_SIZE] = {0};
    bool is_logged_in = false;

    while ((bytes_read = read(client_socket, buffer, BUFFER_SIZE)) > 0) {
        buffer[bytes_read] = '\0';
        printf("Received from client: %s\n", buffer);

        char response[BUFFER_SIZE] = {0};

        char *command = strtok(buffer, " ");
        printf("Debug: Command received: %s\n", command);

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
                continue;
            } else if (sub_command != NULL && strcmp(sub_command, "CHANNEL") == 0) {
                if (is_logged_in) {
                    list_channels(client_socket);
                } else {
                    snprintf(response, BUFFER_SIZE, "Please login first");
                }
                continue;
            } else {
                snprintf(response, BUFFER_SIZE, "Unknown sub-command: %s", sub_command);
            }
        } else if (strcmp(command, "CREATE") == 0) {
            char *sub_command = strtok(NULL, " ");
            if (sub_command != NULL && strcmp(sub_command, "CHANNEL") == 0) {
                if (is_logged_in && (strcmp(current_role, "ROOT") == 0 || strcmp(current_role, "USER") == 0)) {
                    char *channel = strtok(NULL, " ");
                    strtok(NULL, " "); // Skip -k
                    char *key = strtok(NULL, " ");
                    if (create_channel(channel, key, current_username, response)) {
                        snprintf(response, BUFFER_SIZE, "Channel %s dibuat", channel);
                    }
                } else {
                    snprintf(response, BUFFER_SIZE, "Permission denied");
                }
            }
        } else if (strcmp(command, "JOIN") == 0) {
            if (is_logged_in) {
                char *channel = strtok(NULL, " ");
                char *key = NULL;
                if (strcmp(current_role, "USER") == 0) {
                    write(client_socket, "Key: ", 5);
                    bytes_read = read(client_socket, buffer, BUFFER_SIZE);
                    buffer[bytes_read] = '\0';
                    key = strtok(buffer, "\n");
                }
                if (join_channel(current_username, channel, key, response, current_role)) {
                    snprintf(current_channel, BUFFER_SIZE, "%s", channel);
                    snprintf(response, BUFFER_SIZE, "%s/%s", current_username, current_channel);
                }
            } else {
                snprintf(response, BUFFER_SIZE, "Please login first");
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
        } else if (strcmp(command, "LIST") == 0 && is_logged_in) {
            char *sub_command = strtok(NULL, " ");
            if (strcmp(sub_command, "USER") == 0 && current_channel[0] != '\0') {
                char channel_user_path[BUFFER_SIZE];
                snprintf(channel_user_path, BUFFER_SIZE, "%s/%s/admin/auth.csv", BASE_PATH, current_channel);
                FILE *fp = fopen(channel_user_path, "r");
                if (fp != NULL) {
                    char line[BUFFER_SIZE];
                    while (fgets(line, sizeof(line), fp)) {
                        write(client_socket, line, strlen(line));
                    }
                    fclose(fp);
                }
                continue;
            } else {
                snprintf(response, BUFFER_SIZE, "Unknown sub-command: %s", sub_command);
            }
        }

        write(client_socket, response, strlen(response));
    }

    close(client_socket);
}

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    if (setsid() < 0) exit(EXIT_FAILURE);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    umask(0);
    chdir("/");
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }
}

void ensure_files_exist() {
    FILE *fp;

    fp = fopen(FILE_PATH, "a");
    if (fp != NULL) fclose(fp);

    fp = fopen(CHANNELS_PATH, "a");
    if (fp != NULL) fclose(fp);
}

bool register_user(const char *username, const char *password, char *response) {
    FILE *fp = fopen(FILE_PATH, "r");
    if (fp == NULL) {
        snprintf(response, BUFFER_SIZE, "Cannot open users file");
        return false;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), fp)) {
        char existing_username[BUFFER_SIZE];
        sscanf(line, "%*d,%[^,]", existing_username);
        if (strcmp(existing_username, username) == 0) {
            snprintf(response, BUFFER_SIZE, "User %s already exists", username);
            fclose(fp);
            return false;
        }
    }
    fclose(fp);

    char salt[BCRYPT_HASHSIZE];
    char hashed_password[BCRYPT_HASHSIZE];
    if (bcrypt_gensalt(12, salt) != 0 || bcrypt_hashpw(password, salt, hashed_password) != 0) {
        snprintf(response, BUFFER_SIZE, "Password hashing failed");
        return false;
    }

    fp = fopen(FILE_PATH, "a");
    if (fp == NULL) {
        snprintf(response, BUFFER_SIZE, "Cannot open users file");
        return false;
    }

    fseek(fp, 0, SEEK_END);
    long id = ftell(fp) > 0 ? ftell(fp) + 1 : 1;
    fprintf(fp, "%ld,%s,%s,%s\n", id, username, hashed_password, "USER");
    fclose(fp);
    return true;
}

bool login_user(const char *username, const char *password, char *response, char *role) {
    FILE *fp = fopen(FILE_PATH, "r");
    if (fp == NULL) {
        snprintf(response, BUFFER_SIZE, "Cannot open users file");
        return false;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), fp)) {
        char stored_username[BUFFER_SIZE];
        char stored_password[BUFFER_SIZE];
        sscanf(line, "%*d,%[^,],%[^,],%s", stored_username, stored_password, role);
        if (strcmp(stored_username, username) == 0) {
            fclose(fp);
            if (bcrypt_checkpw(password, stored_password) == 0) {
                return true;
            } else {
                snprintf(response, BUFFER_SIZE, "Password incorrect");
                return false;
            }
        }
    }

    snprintf(response, BUFFER_SIZE, "User %s not found", username);
    fclose(fp);
    return false;
}

bool create_channel(const char *channel, const char *key, const char *username, char *response) {
    FILE *fp = fopen(CHANNELS_PATH, "r");
    if (fp == NULL) {
        snprintf(response, BUFFER_SIZE, "Cannot open channels file");
        return false;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), fp)) {
        char existing_channel[BUFFER_SIZE];
        sscanf(line, "%*d,%[^,]", existing_channel);
        if (strcmp(existing_channel, channel) == 0) {
            snprintf(response, BUFFER_SIZE, "Channel %s already exists", channel);
            fclose(fp);
            return false;
        }
    }
    fclose(fp);

    char salt[BCRYPT_HASHSIZE];
    char hashed_key[BCRYPT_HASHSIZE];
    if (bcrypt_gensalt(12, salt) != 0 || bcrypt_hashpw(key, salt, hashed_key) != 0) {
        snprintf(response, BUFFER_SIZE, "Key hashing failed");
        return false;
    }

    fp = fopen(CHANNELS_PATH, "a");
    if (fp == NULL) {
        snprintf(response, BUFFER_SIZE, "Cannot open channels file");
        return false;
    }

    fseek(fp, 0, SEEK_END);
    long id = ftell(fp) > 0 ? ftell(fp) + 1 : 1;
    fprintf(fp, "%ld,%s,%s\n", id, channel, hashed_key);
    fclose(fp);

    char channel_path[BUFFER_SIZE];
    snprintf(channel_path, BUFFER_SIZE, "%s/%s", BASE_PATH, channel);
    mkdir(channel_path, 0755);
    mkdir(strcat(channel_path, "/admin"), 0755);

    snprintf(channel_path, BUFFER_SIZE, "%s/%s/admin/auth.csv", BASE_PATH, channel);
    fp = fopen(channel_path, "a");
    if (fp == NULL) {
        snprintf(response, BUFFER_SIZE, "Cannot create auth file");
        return false;
    }
    fprintf(fp, "id_user,name,role\n1,%s,ADMIN\n", username);
    fclose(fp);

    snprintf(channel_path, BUFFER_SIZE, "%s/%s/admin/users.log", BASE_PATH, channel);
    fp = fopen(channel_path, "a");
    if (fp != NULL) {
        time_t now = time(NULL);
        fprintf(fp, "[%02d/%02d/%02d %02d:%02d:%02d] %s buat %s\n",
                localtime(&now)->tm_mday, localtime(&now)->tm_mon + 1, localtime(&now)->tm_year % 100,
                localtime(&now)->tm_hour, localtime(&now)->tm_min, localtime(&now)->tm_sec,
                username, channel);
        fclose(fp);
    }

    return true;
}


void list_channels(int client_socket) {
    FILE *fp = fopen(CHANNELS_PATH, "r");
    if (fp == NULL) {
        write(client_socket, "Cannot open channels file", 25);
        return;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), fp)) {
        char channel[BUFFER_SIZE];
        sscanf(line, "%*d,%[^,]", channel);
        write(client_socket, channel, strlen(channel));
        write(client_socket, " ", 1);
    }
    fclose(fp);
}

bool join_channel(const char *username, const char *channel, const char *key, char *response, char *role) {
    FILE *fp = fopen(CHANNELS_PATH, "r");
    if (fp == NULL) {
        snprintf(response, BUFFER_SIZE, "Cannot open channels file");
        return false;
    }

    char line[BUFFER_SIZE];
    char stored_key[BCRYPT_HASHSIZE];
    bool channel_found = false;
    while (fgets(line, sizeof(line), fp)) {
        char stored_channel[BUFFER_SIZE];
        sscanf(line, "%*d,%[^,],%s", stored_channel, stored_key);
        if (strcmp(stored_channel, channel) == 0) {
            channel_found = true;
            break;
        }
    }
    fclose(fp);

    if (!channel_found) {
        snprintf(response, BUFFER_SIZE, "Channel %s not found", channel);
        return false;
    }

    if (strcmp(role, "USER") == 0 && bcrypt_checkpw(key, stored_key) != 0) {
        snprintf(response, BUFFER_SIZE, "Incorrect key for channel %s", channel);
        return false;
    }

    char channel_path[BUFFER_SIZE];
    snprintf(channel_path, BUFFER_SIZE, "%s/%s/admin/users.log", BASE_PATH, channel);
    fp = fopen(channel_path, "a");
    if (fp != NULL) {
        time_t now = time(NULL);
        fprintf(fp, "[%02d/%02d/%02d %02d:%02d:%02d] %s masuk ke %s\n",
                localtime(&now)->tm_mday, localtime(&now)->tm_mon + 1, localtime(&now)->tm_year % 100,
                localtime(&now)->tm_hour, localtime(&now)->tm_min, localtime(&now)->tm_sec,
                username, channel);
        fclose(fp);
    }

    return true;
}

bool edit_user(const char *username, const char *new_username, const char *new_password, char *response) {
    FILE *fp = fopen(FILE_PATH, "r+");
    if (fp == NULL) {
        snprintf(response, BUFFER_SIZE, "Cannot open users file");
        return false;
    }

    char line[BUFFER_SIZE];
    char new_file_content[BUFFER_SIZE * 10] = {0};
    bool user_found = false;
    while (fgets(line, sizeof(line), fp)) {
        char stored_username[BUFFER_SIZE];
        sscanf(line, "%*d,%[^,]", stored_username);
        if (strcmp(stored_username, username) == 0) {
            user_found = true;
            char id[BUFFER_SIZE];
            char stored_password[BUFFER_SIZE];
            char role[BUFFER_SIZE];
            sscanf(line, "%[^,],%*[^,],%[^,],%s", id, stored_password, role);
            if (new_username) {
                snprintf(line, BUFFER_SIZE, "%s,%s,%s,%s\n", id, new_username, stored_password, role);
            } else if (new_password) {
                char salt[BCRYPT_HASHSIZE];
                char hashed_password[BCRYPT_HASHSIZE];
                if (bcrypt_gensalt(12, salt) != 0 || bcrypt_hashpw(new_password, salt, hashed_password) != 0) {
                    snprintf(response, BUFFER_SIZE, "Password hashing failed");
                    fclose(fp);
                    return false;
                }
                snprintf(line, BUFFER_SIZE, "%s,%s,%s,%s\n", id, stored_username, hashed_password, role);
            }
        }
        strncat(new_file_content, line, BUFFER_SIZE * 10);
    }

    if (!user_found) {
        snprintf(response, BUFFER_SIZE, "User %s not found", username);
        fclose(fp);
        return false;
    }

    fp = freopen(FILE_PATH, "w", fp);
    if (fp == NULL) {
        snprintf(response, BUFFER_SIZE, "Cannot open users file");
        return false;
    }

    fputs(new_file_content, fp);
    fclose(fp);
    return true;
}


bool edit_profile_self(const char *current_username, const char *new_username, const char *new_password, char *response) {
    return edit_user(current_username, new_username, new_password, response);
}

bool remove_user(const char *username, char *response) {
    FILE *fp = fopen(FILE_PATH, "r");
    if (fp == NULL) {
        snprintf(response, BUFFER_SIZE, "Cannot open users file");
        return false;
    }

    char line[BUFFER_SIZE];
    char new_file_content[BUFFER_SIZE * 10] = {0};
    bool user_found = false;
    while (fgets(line, sizeof(line), fp)) {
        char stored_username[BUFFER_SIZE];
        sscanf(line, "%*d,%[^,]", stored_username);
        if (strcmp(stored_username, username) != 0) {
            strncat(new_file_content, line, BUFFER_SIZE * 10);
        } else {
            user_found = true;
        }
    }
    fclose(fp);

    if (!user_found) {
        snprintf(response, BUFFER_SIZE, "User %s not found", username);
        return false;
    }

    fp = fopen(FILE_PATH, "w");
    if (fp == NULL) {
        snprintf(response, BUFFER_SIZE, "Cannot open users file");
        return false;
    }

    fputs(new_file_content, fp);
    fclose(fp);
    return true;
}

void list_users(int client_socket) {
    FILE *fp = fopen(FILE_PATH, "r");
    if (fp == NULL) {
        write(client_socket, "Cannot open users file", 23);
        return;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), fp)) {
        char username[BUFFER_SIZE];
        sscanf(line, "%*d,%[^,]", username);
        write(client_socket, username, strlen(username));
        write(client_socket, " ", 1);
    }
    fclose(fp);
}
