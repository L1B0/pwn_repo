#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'L1B0'

from pwn import *
import os
from socket import *
context.log_level = 'debug'

#libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6') 
argv = []
dic = []

#log_level2 
stdinr,stdinw = os.pipe()
stderrr,stderrw = os.pipe()
os.write(stdinw,"\x00\x0a\x00\xff")
os.write(stderrw,"\x00\x0a\x02\xff")
	
#level1	
argv = [ "a" for i in range(100) ]
#argv[0] = "./input"
argv[0] = "/home/input2/input"
argv[ord('A')] = "\x00"
#print libc.strcmp(sys.argv[ord('A')],"\x00")
argv[ord('B')] = "\x20\x0a\x0d"
argv[ord('C')] = "8888"

#level3
dic = {"\xde\xad\xbe\xef":"\xca\xfe\xba\xbe"}


#level4 
with open("\x0a",'w') as x:
	x.write("\x00\x00\x00\x00")
	x.close()

if __name__ ==  "__main__":
	
	sd = socket(AF_INET, SOCK_STREAM)

	io = process( argv = argv,  env = dic, stdin = stdinr, stderr = stderrr )
	 
	#level5
	
	host = "127.0.0.1"
	port = int(argv[ord('C')])

	sd.connect((host,port))
	sd.send("\xde\xad\xbe\xef")
	sd.close()

	io.interactive()
	io.close()
