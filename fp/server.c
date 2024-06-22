#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <bcrypt.h>
#include <fcntl.h>

#define PORT 8080
#define USER_FILE "/home/kali/Sisop/FP/DiscorIT/users.csv"
#define BUF_SIZE 256

char usernameglobal[256];


void create_channel(const char *channel_name, const char *key, const char *username, char *response) {
    char path[BUF_SIZE];
    snprintf(path, sizeof(path), "/home/kali/Sisop/FP/DiscorIT/channels.csv");
    FILE *file = fopen(path, "r+");
    if (!file) {
        file = fopen(path, "w+");
        if (!file) {
            perror("Failed to open or create channels.csv");
            exit(EXIT_FAILURE);
        }
    }

    int channel_id = 1;
    fseek(file, 0, SEEK_SET);
    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        char stored_channel_name[BUF_SIZE];
        sscanf(line, "%*d,%[^,],%*s", stored_channel_name);
        if (strcmp(stored_channel_name, channel_name) == 0) {
            snprintf(response, BUF_SIZE, "Channel '%s' already exists. Please choose another name.", channel_name);
            fclose(file);
            return;
        }
        channel_id++;
    }

    char salt[BCRYPT_HASHSIZE];
    char hash[BCRYPT_HASHSIZE];
    bcrypt_gensalt(12, salt);
    bcrypt_hashpw(key, salt, hash);

    fprintf(file, "%d,%s,%s\n", channel_id, channel_name, hash);
    fclose(file);

    char channel_dir[BUF_SIZE];
    snprintf(channel_dir, sizeof(channel_dir), "/home/kali/Sisop/FP/DiscorIT/%s", channel_name);
    mkdir(channel_dir, 0777);

    char admin_dir[BUF_SIZE];
    snprintf(admin_dir, sizeof(admin_dir), "%s/admin", channel_dir);
    mkdir(admin_dir, 0777);

    char auth_file[BUF_SIZE];
    snprintf(auth_file, sizeof(auth_file), "%s/auth.csv", admin_dir);
    file = fopen(auth_file, "w");
    if (!file) {
        perror("Failed to open auth.csv");
        exit(EXIT_FAILURE);
    }
    fprintf(file, "1,%s,ADMIN\n", username);
    fclose(file);

    snprintf(response, BUF_SIZE, "Channel '%s' created successfully", channel_name);
}

void list_channels(char *response) {
    char path[BUF_SIZE];
    snprintf(path, sizeof(path), "/home/kali/Sisop/FP/DiscorIT/channels.csv");
    FILE *file = fopen(path, "r");
    if (!file) {
        perror("Failed to open channels.csv");
        exit(EXIT_FAILURE);
    }

    char line[BUF_SIZE];
    char channel_name[BUF_SIZE];
    bzero(response, BUF_SIZE);
    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%*d,%[^,],%*s", channel_name);
        strcat(response, channel_name);
        strcat(response, " ");
    }

    fclose(file);
}

void register_user(const char *username, const char *password, char *response) {
    if (user_exists(username)) {
        snprintf(response, BUF_SIZE, "Username '%s' already registered", username);
        return;
    }

    FILE *file = fopen(USER_FILE, "a+");
    if (!file) {
        perror("Failed to open user file");
        exit(EXIT_FAILURE);
    }

    int user_id = 1;
    fseek(file, 0, SEEK_SET);
    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        user_id++;
    }

    char salt[BCRYPT_HASHSIZE];
    char hash[BCRYPT_HASHSIZE];
    bcrypt_gensalt(12, salt);
    bcrypt_hashpw(password, salt, hash);

    const char *role = (user_id == 1) ? "ROOT" : "USER";
    fprintf(file, "%d,%s,%s,%s\n", user_id, username, hash, role);
    fclose(file);

    snprintf(response, BUF_SIZE, "User '%s' registered successfully", username);
}

bool login_user(const char *username, const char *password, char *response) {
    FILE *file = fopen(USER_FILE, "r");
    if (!file) {
        perror("Failed to open user file");
        snprintf(response, BUF_SIZE, "Failed to login user\n");
        return 0;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        char stored_username[BUF_SIZE], stored_hash[BCRYPT_HASHSIZE];
        sscanf(line, "%*d,%[^,],%[^,],%*s", stored_username, stored_hash);
        if (strcmp(stored_username, username) == 0) {
            int check = bcrypt_checkpw(password, stored_hash);
            if (check == 0) {
                fclose(file);
                snprintf(response, BUF_SIZE, "berhasil");
                return 1;
            } else if (check == -1) {
                fclose(file);
                snprintf(response, BUF_SIZE, "Error checking password for %s\n", username);
            } else {
                fclose(file);
                snprintf(response, BUF_SIZE, "Incorrect password for %s\n", username);
            }
            return 0;
        }
    }

    fclose(file);
    snprintf(response, BUF_SIZE, "Username %s not found\n", username);
    return 0;
}

int user_exists(const char *username) {
    FILE *file = fopen(USER_FILE, "r");
    if (!file) {
        return 0;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        char stored_username[BUF_SIZE];
        sscanf(line, "%*d,%[^,],%*[^,],%*s", stored_username);
        if (strcmp(stored_username, username) == 0) {
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}

void *client_handler(void *newsockfd) {
    int sock = *(int *)newsockfd;
    free(newsockfd);
    char buffer[256];
    ssize_t n;

    while (1) {
        bzero(buffer, 256);
        n = read(sock, buffer, 255);
        if (n < 0) {
            perror("ERROR reading from socket");
            close(sock);
            return NULL;
        }

        if (n == 0) {
            close(sock);
            return NULL;
        }

        printf("Here is the message: %s\n", buffer);

        char *command = strtok(buffer, " ");
        char response[BUF_SIZE] = {0};

        if (strcmp(command, "REGISTER") == 0) {
            char *username = strtok(NULL, " ");
            strtok(NULL, " "); // skip "-p"
            char *password = strtok(NULL, " ");
            register_user(username, password, response);
        } else if (strcmp(command, "LOGIN") == 0) {
            char *username = strtok(NULL, " ");
            strtok(NULL, " "); // skip "-p"
            char *password = strtok(NULL, " ");
            if (login_user(username, password, response)) {
                strcpy(usernameglobal, username); // copy username to global variable
            }
        } else if (strcmp(command, "CREATE") == 0) {
            char *arg3 = strtok(NULL, " ");
            if (strcmp(arg3, "CHANNEL") == 0) {
                char *channel_name = strtok(NULL, " ");
                strtok(NULL, " "); // skip "-k"
                char *key = strtok(NULL, " ");
                create_channel(channel_name, key, usernameglobal, response);
            }
        } else if (strcmp(command, "LIST") == 0) {
            char *arg3 = strtok(NULL, " ");
            if (strcmp(arg3, "CHANNEL") == 0) {
                list_channels(response);
            }
        } else {
            snprintf(response, BUF_SIZE, "Unknown command");
        }

        n = write(sock, response, strlen(response));
        if (n < 0) {
            perror("ERROR writing to socket");
            close(sock);
            return NULL;
        }
    }
}


void mulai_daemon() {
    pid_t pid;
    pid = fork();

    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    umask(0);
    setsid();
    chdir("/");
}

void mulai_socket() {
    int sockfd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket");
        exit(1);
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR on binding");
        exit(1);
    }

    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    while (1) {
        int *newsockfd = malloc(sizeof(int));
        *newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (*newsockfd < 0) {
            perror("ERROR on accept");
            free(newsockfd);
            continue;
        }

        pthread_t t;
        pthread_create(&t, NULL, client_handler, newsockfd);
    }

    close(sockfd);
}

int main() {
    mulai_daemon();
    mulai_socket();
    return 0;
}
