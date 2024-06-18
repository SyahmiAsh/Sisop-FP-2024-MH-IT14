# Sisop-FP-2024-MH-IT14

gcc -o server server.c -L/usr/local/lib -lbcrypt
gcc -o discorit discorit.c 

./server

./discorit LOGIN new_username -p password

./discorit REGISTER username2 -p password2

##diluar channel

┌──(kali㉿kali)-[~/Documents/fp]
└─$ ./discorit LOGIN new_username -p password
Server response: new_username berhasil login
[new_username] LIST USER
Server response: new_username userchange username4 
^C

root

[user] LIST USER
[user] EDIT WHERE user1 -u user01
[user] EDIT WHERE user01 -p secretpass
[user] REMOVE user01

user
[user] EDIT PROFILE SELF -u new_username
[user] EDIT PROFILE SELF -p new_password

##channel

CREATE CHANNEL care -k care123

┌──(kali㉿kali)-[~/Documents/fp]
└─$ ./discorit LOGIN new_username -p password
Server response: new_username berhasil login
[new_username] CREATE CHANNEL care -k care123    
Server response: Channel care dibuat

LIST CHANNEL

┌──(kali㉿kali)-[~/Documents/fp]
└─$ ./discorit LOGIN username4 -p password4
Server response: username4 berhasil login
[username4] LIST CHANNEL
Server response: care 
LIST CHANNEL
Server response: care 

JOIN care

┌──(kali㉿kali)-[~/Documents/fp]
└─$ ./discorit LOGIN new_username -p password 
Server response: new_username berhasil login
[new_username] JOIN care
Server response: new_username/care
[new_username/care] hai

LIST USER





                                                                                                                                                                               
