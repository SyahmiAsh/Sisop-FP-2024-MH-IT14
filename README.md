# Sisop-FP-2024-MH-IT14
Laporan pengerjaan Final Project Sistem Operasi 2024 oleh Kelompok IT14
## Praktikan Sistem Operasi Kelompok IT14
1. Tsaldia Hukma Cita          : 5027231036
2. Muhammad Faqih Husain       : 5027231023
3. Muhammad Syahmi Ash Shidqi  : 5027231085

## DiscorIT
### Bagaimana Program Diakses
- Untuk mengakses DiscorIT, user perlu membuka program client (discorit). discorit hanya bekerja sebagai client yang mengirimkan request user kepada server.
- Program server berjalan sebagai server yang menerima semua request dari client dan mengembalikan response kepada client sesuai ketentuan pada soal. Program server berjalan sebagai daemon. 
- Untuk hanya menampilkan chat, user perlu membuka program client (monitor). Lebih lengkapnya pada poin monitor.
- Program client dan server berinteraksi melalui socket.
- Server dapat terhubung dengan lebih dari satu client.

### Disclaimer
Program server, discorit, dan monitor TIDAK DIPERBOLEHKAN menggunakan perintah system();

### Tree
```
DiscorIT/
      - channels.csv
      - users.csv
      - channel1/
               - admin/
                        - auth.csv
                        - user.log
               - room1/
                        - chat.csv
               - room2/
                        - chat.csv
               - room3/
                        - chat.csv
      - channel2/
               - admin/
                        - auth.csv
                        - user.log
               - room1/
                        - chat.csv
               - room2/
```
### Keterangan setiap file
| Nama File  | Isi File |
| ------------- | ------------- |
|  users.csv  | id_user	int (mulai dari 1)  |
|  | name string |
|  | password string (di encrypt menggunakan bcrypt biar ga tembus) |
|  | global_role string (pilihannya: ROOT / USER) |
| channels.csv | id_channel int  (mulai dari 1) |
|  | channel string |
|  | key string (di encrypt menggunakan bcrypt biar ga tembus)|
| auth.csv | id_user int |
|  | name string |
|  | role string (pilihannya: ROOT/ADMIN/USER/BANNED) | 
| user.log| [dd/mm/yyyy HH:MM:SS] admin buat room1 |
||[dd/mm/yyyy HH:MM:SS] user1 masuk ke channel “say hi”|
||[dd/mm/yyyy HH:MM:SS] admin memberi role1 kepada user1|
||[dd/mm/yyyy HH:MM:SS] admin ban user1|
|chat.csv| date int|
||id_chat number (mulai dari 1)|
||sender string|
||chat string|

### Program discorit.c
Program discorit.c merupakan program client yang berfungsi untuk terhubung dengan server chat melalui socket. Program ini memungkinkan pengguna untuk melakukan beberapa operasi dasar seperti login, bergabung dengan channel, membuat room dalam channel, dan keluar dari program. Berikut adalah penjelasan lengkap mengenai kode tersebut dan fungsinya:
#### 1. Header dan Deklarasi Global
```c
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
```
- Header menyertakan pustaka yang diperlukan untuk operasi input/output (stdio.h), manajemen memori (stdlib.h), manajemen string (string.h), operasi sistem POSIX (unistd.h), dan operasi socket (sys/types.h, sys/socket.h, netinet/in.h, netdb.h).
- Makro: Mendefinisikan port server (PORT) dan ukuran buffer (BUF_SIZE).
- Dalam program ini menggunakan variabel global seperti berikut ini,
  - login: Menyimpan status login (0 = belum login, 1 = sudah login).
  - username, channel, room: Menyimpan informasi username, nama channel, dan nama room.

#### 2. Fungsi 'error'
Fungsi 'error' dalam program ini berguna untuk menampilkan pesan error ketika terjadi kesalahan dan keluar dari program

      void error(const char *msg)
      {
          perror(msg);
          exit(1);
      }


#### 3. Fungsi 'main'
Pada fungsi ini terdapat beberapa fitur di dalamnya, seperti mengisiasi dan validasi argumen, menghubungkan dengan server, mengirim data menuju server, membaca respon dari user. Berikut ini merupakan kode untuk melakukan tugas tersebut
- Mengisiasi dan validasi argumen
  
      int main(int argc, char *argv[])
      {
          int sockfd;
          struct sockaddr_in serv_addr;
          struct hostent *server;
          char buffer[BUF_SIZE];
      
          if (argc < 4)
          {
              fprintf(stderr, "usage: %s command username password\n", argv[0]);
              exit(0);
          }
- Menghubungkan dengan server

            sockfd = socket(AF_INET, SOCK_STREAM, 0);
          if (sockfd < 0)
              error("ERROR opening socket");
      
          server = gethostbyname("localhost");
          if (server == NULL)
          {
              fprintf(stderr, "ERROR, no such host\n");
              exit(0);
          }
      
          bzero((char *)&serv_addr, sizeof(serv_addr));
          serv_addr.sin_family = AF_INET;
          bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
          serv_addr.sin_port = htons(PORT);
      
          if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
              error("ERROR connecting");
- Mengirim data menuju server

          if (argc == 3)
          {
              sprintf(buffer, "%s %s", argv[1], argv[2]);
          }
          else if (argc == 4)
          {
              sprintf(buffer, "%s %s %s", argv[1], argv[2], argv[3]);
          }
          else if (argc == 5)
          {
              sprintf(buffer, "%s %s %s %s", argv[1], argv[2], argv[3], argv[4]);
          }
          else if (argc == 6)
          {
              sprintf(buffer, "%s %s %s %s %s", argv[1], argv[2], argv[3], argv[4], argv[5]);
          }
      
          write(sockfd, buffer, strlen(buffer));
- Membaca respon dari server

          bzero(buffer, BUF_SIZE);
          ssize_t n = read(sockfd, buffer, BUF_SIZE - 1);
          if (n < 0)
              error("ERROR reading from socket");
      
          printf("%s\n", buffer);
          if (strncmp("berhasil", buffer, 8) == 0)
          {
              login = 1;
          }
- Loop interaksi user setelah login

          if (login)
          {
              strcpy(username, argv[2]);
              while (1)
              {
                  if (strlen(channel) > 0)
                  {
                      printf("[%s/%s] ", username, channel);
                  }
                  else
                  {
                      printf("[%s] ", username);
                  }

            bzero(buffer, BUF_SIZE);
            fgets(buffer, BUF_SIZE - 1, stdin);
##### Fitur Create Room 
Didalam program discorit.c terdapat sebuah fitur untuk membuat room yang terdapat di dalam sebuah channel. Fitur ini dapat membantu untuk membuat sebuah room baru di dalam channel

            else if (strncmp("CREATE ROOM", buffer, 11) == 0)
            {
                if (strlen(channel) == 0)
                {
                    printf("You need to join a channel first\n");
                    continue;
                }
                char *room_name = strtok(buffer + 12, " \n");

                if (room_name)
                {
                    char command[BUF_SIZE];
                    strcpy(command, "CREATE ROOM ");
                    strcat(command, channel);
                    strcat(command, " ");
                    strcat(command, room_name);
                    snprintf(buffer, BUF_SIZE, "%s", command);

                    write(sockfd, buffer, strlen(buffer));
                    bzero(buffer, BUF_SIZE);
                    n = read(sockfd, buffer, BUF_SIZE - 1);
                    if (n < 0)
                        error("ERROR reading from socket");
                    printf("%s\n", buffer);
                    continue;
                }
                else
                {
                    printf("Usage: CREATE ROOM <room_name>\n");
                    continue;
                }
            }
Untuk dapat menjalankan fitur ini dapat dilakukan dengan format command seperti berikut ini 

      [user/channel] CREATE ROOM room 
      Room room dibuat

##### Fitur Join Channel 
Dalam program untuk fitur join channel ini dibuat dengan tujuan user dapat bergabung/join menuju channel yang telah tersedia. Berikut merupakan kode untuk menjalankan fitur tersebut 
               
                  if (strncmp("JOIN", buffer, 4) == 0)
                  {
                      char *channel_name = strtok(buffer + 5, " \n");
                      if (channel_name)
                      {
                          sprintf(buffer, "JOIN %s", channel_name);
                          write(sockfd, buffer, strlen(buffer));
                          bzero(buffer, BUF_SIZE);
                          n = read(sockfd, buffer, BUF_SIZE - 1);
                          if (n < 0)
                              error("ERROR reading from socket");
                          printf("%s\n", buffer);
                          if (strstr(buffer, "User") != NULL && strstr(buffer, "joined channel") != NULL)
                          {
                              sscanf(buffer, "User '%*[^']' joined channel '%49[^']'", channel);
                          }
                          continue;
                      }
                  }

Untuk menjalankan fitur ini dapat dilakukan dengan format seperti berikut ini 
- Untuk admin dan root 
     
      [user] JOIN channel
      [user/channel] 
- Bagi user yang baru pertamakali masuk channel akan dibatasi aksesnya, sehingga terdapat key. Ketika user sudah pernah masuk maka user tidak perlu mengisi key

      [user] JOIN channel
      Key: key
      [user/channel]

### Program server.c
Program server berjalan sebagai server yang menerima semua request dari client dan mengembalikan response kepada client sesuai ketentuan pada soal. Program server berjalan sebagai daemon. Berikut adalah penjelasan lengkap mengenai kode tersebut dan fungsinya:
#### 1. Header dan Deklarasi Global
```
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
#include <ctype.h>

#define PORT 8080
#define USER_FILE "/home/kali/Sisop/FP/DiscorIT/users.csv"
#define BUF_SIZE 256
#define BUFFER_SIZE 1024
```
- Header menyertakan pustaka yang diperlukan untuk operasi input/output (stdio.h), manajemen memori (stdlib.h), manajemen string (string.h), operasi sistem POSIX (unistd.h), operasi socket (sys/types.h, sys/socket.h, netinet/in.h), manajemen thread (pthread.h), mengelola atribut file (sys/stat.h), data boolean (stdbool.h), encrypt bcrypt (bcrypt.h), operasi kontrol file (fcntl.h), dan manipulasi teks (ctype.h)
- Makro: Mendefinisikan port server (PORT), ukuran buffer (BUF_SIZE) (BUFFER_SIZE), dan path dari users.csv (USER_FILE)

#### 2. Fungsi 'list_channels'  
Fungsi list_channels bertujuan untuk membaca semua nama channel dari sebuah file CSV bernama `channels.csv` dan menggabungkannya menjadi satu string yang disimpan dalam variabel `response`
```
void list_channels(char *response) {
    char path[BUF_SIZE];
    snprintf(path, sizeof(path), "/home/kali/Sisop/FP/DiscorIT/channels.csv");
    FILE *file = fopen(path, "r");
    if (!file) {
        perror("Failed to open channels.csv");
        exit(EXIT_FAILURE);
    }

    char line[BUF_SIZE];
    char channels[BUF_SIZE] = "";
    while (fgets(line, sizeof(line), file)) {
        char channel_name[BUF_SIZE];
        sscanf(line, "%*d,%[^,],%*s", channel_name);
        strcat(channels, channel_name);
        strcat(channels, " ");
    }
    fclose(file);

    snprintf(response, BUF_SIZE, "%s", channels);
}
```

#### 2. Fungsi 'create_directory'
Fungsi create_directory bertujuan untuk membuat sebuah direktori baru dengan path yang diberikan dan mengirimkan respon ke klien melalui socket jika terjadi kegagalan

```
void create_directory(const char *path, int socket) {
    if (mkdir(path, 0777) == -1) {
        perror("Failed to create directory");
        char response[] = "Failed to create directory";
        if (write(socket, response, strlen(response)) < 0) {
            perror("Failed to send response to client");
        }
        exit(EXIT_FAILURE);
    }
}
```

### 3. Fungsi 'log_activity'
```
void log_activity(const char *channel, const char *log_message) {
    char log_path[256];
    snprintf(log_path, sizeof(log_path), "/home/kali/Sisop/FP/DiscorIT/%s/admin/log.csv", channel);
    FILE *log_file = fopen(log_path, "a");
    if (log_file) {
        fprintf(log_file, "%s\n", log_message);
        fclose(log_file);
    } else {
        perror("Failed to open log.csv");
    }
}
```
### 4. Fungsi 'create_room'
```
void create_room(const char *username, const char *channel, const char *room, int socket) {
    char auth_path[256];
    snprintf(auth_path, sizeof(auth_path), "/home/kali/Sisop/FP/DiscorIT/%s/admin/auth.csv", channel);

    FILE *auth_file = fopen(auth_path, "r");
    if (!auth_file) {
        char response[] = "Failed to open auth.csv or you are not joined in the channel";
        if (write(socket, response, strlen(response)) < 0) {
            perror("Failed to send response to client");
        }
        return;
    }

    char line[256];
    bool is_admin = false;
    bool is_root = false;

    while (fgets(line, sizeof(line), auth_file)) {
        char *token = strtok(line, ",");
        if (token == NULL) continue;
        token = strtok(NULL, ",");
        if (token == NULL) continue;
        if (strcmp(token, username) == 0) {
            token = strtok(NULL, ",");
            if (strstr(token, "ADMIN") != NULL) {
                is_admin = true;
            } else if (strstr(token, "ROOT") != NULL) {
                is_root = true;
            }
        }
    }

    fclose(auth_file);

    if (!is_admin && !is_root) {
        char response[] = "You do not have permission to create a room in this channel";
        if (write(socket, response, strlen(response)) < 0) {
            perror("Failed to send response to client");
        }
        return;
    }

    char check_path[256];
    snprintf(check_path, sizeof(check_path), "/home/kali/Sisop/FP/DiscorIT/%s/%s", channel, room);
    struct stat st;
    if (stat(check_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        char response[] = "Room name is already used";
        if (write(socket, response, strlen(response)) < 0) {
            perror("Failed to send response to client");
        }
        return;
    }

    char path[256];
    snprintf(path, sizeof(path), "/home/kali/Sisop/FP/DiscorIT/%s/%s", channel, room);
    create_directory(path, socket);

    snprintf(path, sizeof(path), "/home/kali/Sisop/FP/DiscorIT/%s/%s/chat.csv", channel, room);
    FILE *chat_file = fopen(path, "w+");
    if(chat_file){
        fclose(chat_file);
    }else{
        char response[] = "Failed to create chat.csv file";
        if (write(socket, response, strlen(response)) < 0) {
            perror("Failed to send response to client");
        }
        return;
    }
    
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Room %s created", room);
    if (write(socket, response, strlen(response)) < 0) {
        perror("Failed to send response to client");
    }

    char log_message[100];
    if(is_root){
        snprintf(log_message, sizeof(log_message), "ROOT created room %s", room);
    }else{
        snprintf(log_message, sizeof(log_message), "ADMIN created room %s", room);
    }
    log_activity(channel, log_message);
}

```

### 5. Fungsi 'trim_whitespace'
```
void trim_whitespace(char *str) {
    char *end;

    // Trim leading space
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0) {
        // All spaces?
        return;
    }

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    // Write new null terminator character
    *(end + 1) = 0;
}
```

### 6. Fungsi 'join_channel'
```
void join_channel(const char *channel_name, const char *username, char *response) {
    char trimmed_channel_name[BUF_SIZE];
    strncpy(trimmed_channel_name, channel_name, BUF_SIZE);
    trimmed_channel_name[BUF_SIZE - 1] = '\0';  // Ensure null-terminated string
    trim_whitespace(trimmed_channel_name);

    char path[BUF_SIZE];
    snprintf(path, sizeof(path), "/home/kali/Sisop/FP/DiscorIT/channels.csv");
    FILE *file = fopen(path, "r");
    if (!file) {
        snprintf(response, BUF_SIZE, "Failed to open channels.csv");
        return;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        char stored_channel_name[BUF_SIZE];
        sscanf(line, "%*d,%[^,],%*s", stored_channel_name);
        trim_whitespace(stored_channel_name);  // Trim whitespace from the stored channel name

        if (strcmp(stored_channel_name, trimmed_channel_name) == 0) {
            fclose(file);

            char channel_dir[BUF_SIZE];
            snprintf(channel_dir, sizeof(channel_dir), "/home/kali/Sisop/FP/DiscorIT/%s", trimmed_channel_name);

            char user_file[BUF_SIZE];
            snprintf(user_file, sizeof(user_file), "%s/users.csv", channel_dir);
            file = fopen(user_file, "a");
            if (!file) {
                snprintf(response, BUF_SIZE, "Failed to open or create users.csv");
                return;
            }

            fprintf(file, "%s\n", username);
            fclose(file);

            snprintf(response, BUF_SIZE, "User '%s' joined channel '%s' successfully", username, trimmed_channel_name);
            return;
        }
    }

    fclose(file);
    snprintf(response, BUF_SIZE, "Channel '%s' not found", trimmed_channel_name);
}

```
### 7. Fungsi 'create_channel'
```
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
```
### 8. Fungsi 'register_user'
```
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
```
### 9. Fungsi 'Login'
```
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

```

### 10. Fu
```
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
```

### 11. Fungsi
```
void *client_handler(void *newsockfd) {
    char usernameglobal[256];
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
            char *token = strtok(NULL, " ");
            if (token == NULL) {
                strcpy(response, "Format perintah CREATE tidak valid");
            } else if (strcmp(token, "CHANNEL") == 0) {
                char *channel_name = strtok(NULL, " ");
                strtok(NULL, " "); // skip "-k"
                char *key = strtok(NULL, " ");
                create_channel(channel_name, key, usernameglobal, response);
            } else if (strcmp(token, "ROOM") == 0) {
                char *channel_name = strtok(NULL, " ");
                char *room = strtok(NULL, " ");
                
                // Print debug information to validate parsed values
                printf("Parsed channel_name: %s\n", channel_name);
                printf("Parsed room: %s\n", room);

                if (channel_name == NULL || room == NULL) {
                    strcpy(response, "Penggunaan perintah: CREATE ROOM <channel> <room>");
                } else {
                    create_room(usernameglobal, channel_name, room, sock);
                }
            }
        } else if (strcmp(command, "LIST") == 0) {
            list_channels(response);
        } else if (strcmp(command, "JOIN") == 0) {
            char *channel_name = strtok(NULL, " ");
            join_channel(channel_name, usernameglobal, response);
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
```
### 12. Fungsi
```
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
```
### 13. Fungsi
```
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
```

How To Play

- `gcc -o server server.c -L/usr/local/lib -lbcrypt`
- `gcc -o discorit discorit.c`
- `./server`
- `./discorit LOGIN new_username -p password`
- `./discorit REGISTER username2 -p password2`


### Diluar channel
- `[new_username] LIST USER`

root
```
[user] LIST USER
[user] EDIT WHERE user1 -u user01
[user] EDIT WHERE user01 -p secretpass
[user] REMOVE user01
```

user
```
[user] EDIT PROFILE SELF -u new_username
[user] EDIT PROFILE SELF -p new_password
```

### Channel
```
JOIN care
CREATE CHANNEL care -k care123
LIST CHANNEL
LIST USER
```






                                                                                                                                                                               
