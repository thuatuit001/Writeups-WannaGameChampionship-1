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
kali@kali:~/Desktop/WGC August 2020$ ./fms
Is any body here? (yes or no)
Co Hien xinh dep
Co Hien xinh dep
This isn't enough.
```

Có 3 trường hợp như trên. Chúng ta mở file bằng IDA Pro và xem mã giả của hàm `main`:

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

Chương trình cho phép chúng ta nhập vào input dài tối đa 64 ký tự. Trường hợp input không chứa `no` và `yes` thì chương trình in ra input của chúng ta vừa nhập vào. Điều đáng chú ý ở đây là lệnh `printf(&s);` thiếu tham số format string (viết tắt là fms như tên file). Lỗ hổng format string là như thế nào, chúng ta có thể khai thác gì từ nó, cách khai thác như thế nào - xem ở [video 1](https://www.youtube.com/watch?v=0WvrSfcdq1I) và [video 2](https://www.youtube.com/watch?v=t1LH9D5cuK4) (video khá ngắn gọn và dễ hiểu, chỉ cần xem bằng cả con tim là được).

Sau khi in ra input chúng ta nhập vào. Chương trình gọi hàm `check_key`:

```
int check_key()
{
  int result; // eax@2

  if ( key_number == 2020 )
  {
    printf("Good");
    result = cat_flag();
  }
  else
  {
    result = printf("This isn't enough.");
  }
  return result;
}
```

Hàm này kiểm tra nếu giá trị biến toàn cục `key_number` bằng `2020` thì gọi hàm `cat_flag`:

```
int cat_flag()
{
  return system("/bin/sh");
}
```

Vậy việc chúng ta cần làm là lợi dụng lỗ hổng format string để gán giá trị `key_number` bằng `2020`.

## It is simple, but not easy

## RSA 1

## Extract password from registry files
