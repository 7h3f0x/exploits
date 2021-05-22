##  Gryffindor Writeup

This challenge can be solved in 2 ways : 
 - Using the **Unsafe Unlink** vulnerability as there is heap overflow along with global pointers
 - Using the **House Of Force** attack (which i have used) as there is heap overflow with the availabilty of a heap leak

The exploitation for the *house of force* attack is made easier by function to give us a heap leak namely *goodguy* which leakes the address of the first allocated chunk located the base + 0x10 address. This enables us to calculate the heap's base address

I create another chunk 0f size 0x100 + 0x10 with malloc and overflow it to overwrite the top chunk's size. The structure is something like:
> first_chunk_header(0x10)
> first_chunk_data(0x100)
> my_chunk_header(0x10)
> my_chunk_data(0x100)
> top_chunk_metadata(0x8)
> top_chunk_size(0x8)

We overwrite the top_chunk_size with **0xffffffffff** which is the largest 64bit-number. This is so that any further call to malloc with any size can be done by splitting the top chunk instead of resizing it with brk or using mmap.

Now comes the important step, the actual exploit now is to get malloc to return a controlled pointer. In my case i wanted a pointer to the global pointer array `table`. So i used some quick math to figure out the right amount to ask malloc for. A good thing was that the size was taken in `size_t` data type so i didn't have to worry about having to convert my value to an unsigned one myself(Since size_t is unsigned).

> evil_size = victim - top_chunk - 4 \* 8
> the victim is the global array
> top chunk is calculated using the heap base as `base + 0x110 * 2` since two chunks of 0x100 have been allocated along with their headers.

Now calling malloc with this results in:
> new_top = old_top + nb
> nb = new_top - old_top
> req + 2sizeof(long) = new_top - old_top
> req = new_top - old_top - 2sizeof(long)
> req = dest - 2sizeof(long) - old_top - 2sizeof(long)
> req = dest - old_top - 4\*sizeof(long)
> where nb = no. of bytes to be requested

Now , when we call malloc again it services using the new malicious top chunk to give us the pointer to the table.
This completes the house of force attack.

Now i use that pointer to overwrite the array to fill it such that:
> 0th: 0x0000000000
> 1st: elf.symbols['table'] -> the address of the table itself in case I need to write to it again
> 2st: elf.got['free'] -> the got address of free , so that i can overwrite it
> 3rd: elf.got['atoi'] -> any got entry so that i can get a libc leak

Now i first edit the got entry of puts to the plt entry of puts. Now,calling free results in calling puts. *Note that i use only 7 bytes for this overwrite as using all 8 bytes with the nullbyte appended by the edit function was writing some critical memory which was causing a segfault and that was supposed to be a nullbyte anyway*

Now i call delete on the 3rd index resulting in the addresss for the atoi function. I use this to calculate the address of the base of libc.

Now that i have this leak, all that remains is overwriting the got entry of free again, but this time with the address of the **magic gadget** using `one_gadget`on the provided libc + the base offset. I do this, now calling free would get me a shell.

I call delete on the 1st index which executes `/bin/sh`, thereby completing the pwning process.