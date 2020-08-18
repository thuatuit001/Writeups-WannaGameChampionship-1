# Writeups WannaGame Championship #1

@boodamdang

##############################

- [Start pwn](https://github.com/thuatuit001/Writeups-WannaGameChampionship-1/blob/master/README.md#start-pwn)
- [It is simple, but not easy](https://github.com/thuatuit001/Writeups-WannaGameChampionship-1/blob/master/README.md#it-is-simple-but-not-easy)
- [RSA 1](https://github.com/thuatuit001/Writeups-WannaGameChampionship-1/blob/master/README.md#rsa-1)
- [Extract password from registry files](https://github.com/thuatuit001/Writeups-WannaGameChampionship-1/blob/master/README.md#extract-password-from-registry-files)

##############################

## Start pwn

File(s): [fms](https://github.com/thuatuit001/Writeups-WannaGameChampionship-1/blob/master/fms)

fms là gì nhỉ... feel my style? :D. Đầu tiên, chúng ta chạy thử file:

```
kali@kali:~/Desktop/WGC August 2020$ ./fms
Is any body here? (yes or no)
no
Sad !!
kali@kali:~/Desktop/WGC August 2020$ ./fms
Is any body here? (yes or no)
yes
This isn't enough.
```

Chúng ta thấy có 2 trường hợp:

- \[Nữ] Anh có xin lỗi em không? --> \[Nam] Không. --> \[Nữ] Buồn, anh là đồ tồi!
- \[Nữ] Anh có xin lỗi em không? --> \[Nam] Có. --> \[Nữ] Anh nghĩ xin lỗi là xong à? 

## It is simple, but not easy

## RSA 1

## Extract password from registry files
