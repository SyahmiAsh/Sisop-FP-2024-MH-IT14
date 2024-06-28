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

### A.Autentikasi
- Setiap user harus memiliki username dan password untuk mengakses DiscorIT. Username, password, dan global role disimpan dalam file user.csv.
- Jika tidak ada user lain dalam sistem, user pertama yang mendaftar otomatis mendapatkan role "ROOT". Username harus bersifat unique dan password wajib di encrypt menggunakan menggunakan bcrypt.

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

### Program discorit.c
Program discorit.c merupakan program client yang berfungsi untuk terhubung dengan server chat melalui socket. Program ini memungkinkan pengguna untuk melakukan beberapa operasi dasar seperti login, bergabung dengan channel, membuat room dalam channel, dan keluar dari program. Berikut adalah penjelasan lengkap mengenai kode tersebut dan fungsinya:
#### 1. Header dan Deklarasi Global
```
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






                                                                                                                                                                               
