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






                                                                                                                                                                               
