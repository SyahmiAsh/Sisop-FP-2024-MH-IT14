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





                                                                                                                                                                               
