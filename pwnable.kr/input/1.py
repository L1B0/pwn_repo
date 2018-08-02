from pwn import *
context.log_level = 'debug'
#level1	
argv = [ "a" for i in range(100) ]
argv[0] = "./input11"
argv[ord('A')] = "\x00"
#print libc.strcmp(sys.argv[ord('A')],"\x00")
argv[ord('B')] = "\x20\x0a\x0d"
io = process(argv = argv)
io.recv()
