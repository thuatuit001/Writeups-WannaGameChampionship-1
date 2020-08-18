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

Nếu mà người yêu các ông như vậy thì các ông phải làm gì? Đầu tiên chắc chắn phải có xin lỗi, sau đó thì đánh vào điểm yếu của ẻm: ẻm thích quà thì cho em quà, ẻm thích ăn thì cho ẻm ăn, ... Để biết điểm yếu của ẻm là gì thì chúng ta phải hiểu được ẻm - chúng ta dùng IDA Pro để xem mã giả của hàm main:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [sp+0h] [bp-48h]@1

  puts("Is any body here? (yes or no)");
  fflush(stdout);
  fgets(&s, 64, stdin);
  if ( strstr(&s, "no") )
  {
    printf("Sad !!");
    exit(1);
  }
  if ( !strstr(&s, "yes") )
  {
    printf(&s);
    fflush(stdout);
  }
  check_key();
  return 0;
}
```

Sau khi

## It is simple, but not easy

## RSA 1

## Extract password from registry files
