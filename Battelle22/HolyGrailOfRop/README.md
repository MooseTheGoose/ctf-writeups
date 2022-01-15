# Holy Grail of ROP writeup

For this challenge, you must connect using the information below
**URL**: ctf.battelle.org
**Port**: 30042

## Intro to the challenge

When connecting to this challenge, the server outputs 4 lines of header
followed by a series of ELF files that you must find the vulnerability in
and exploit them.

## Extracting the binary

The binary is sent using the following format

**************
ELF data here
**************

which means we can extract the elf and save it in the file system
with the following method

def read_elf(sock, exepath):
    sock.recvline()
    line = sock.recvline()
    elf_bytes = b''
    delim_char = b'*'[0]
    while not all(c == delim_char for c in line.strip()):
         elf_bytes += line
         line = sock.recvline()
    with open(exepath, 'wb') as fp:
        fp.write(elf_bytes)

Great. Now we have the ELF on our system that we can analyze

## Reversing the first binary

It's a very simple program that doesn't do much, frankly.
It doesn't even print anything. All we do is read something
from the command line and close when we're done reading things.

The one interesting thing it does is that, depending on what's
read, it will branch out to different places.

This challenge has to be solvable, so one of the read() calls
in the binary has to overflow somehow, and it does.

Here's what it looks like in Ghidra when I analyzed it.

```
void BufferOverflowExploit(void)
{
  size_t __n;
  char local_31 [33];
  char *local_10;
  
  local_10 = "I\'ll bite your legs off!";
  memset(local_31,0,0x21);
  read(0,local_31,0x100);  // <-- Vulnerable read here
  ...
```

## Automating finding the exploit

The ELF changes every time and there are quite a fair number
of variations, so we need to automate finding the exploit somehow.
This is something that's ideal for the python library 'angr', but
I had trouble getting it to work and actually finding the inputs
required to get to a certain state.

The programs being outputted were actually really simple and mostly
concrete in execution, so a more attractive option for me was to
emulate it and make my own simple, ad-hoc graph describing the routes
I could take in the program. To emulate it, I used Qiling, since it
allowed me to emulate it and hook the libc API calls very easily.

## The Strncmp Graph

For this challenge, I made a graph where the nodes are calls to strncmp
and the edges are the branches, with one branch being that the string read
from the input is equal to the string being compared, and the other branch being
not. The graph and the nodes are defined as classes. These are what they look like.

```
STRNCMP_MATCH = 0
STRNCMP_NOMATCH = 1

class StrncmpNode:
    def __init__(self, s, addr, regs):
        self.arg = s
        self.addr = addr
        self.parent = None
        self.children = [None, None]
        self.regs = regs

class StrncmpGraph:
    def __init__(self):
        self.curr_node = StrncmpNode("", 0, None) 
        self.curr_direction = STRNCMP_MATCH
        self.nodes = []
        self.target = None
```

StrncmpNode
  * parent: The parent of this node, which is the strncmp immediately preceeding the call
  * children: The children of this node, where children[0] is the path taken on equality
  * addr:  The address this node returns to
  * arg: The concrete string being compared to the read string
  * regs: From qiling, the saved registers which can be restored later

StrncmpGraph
  * curr_node: The node whose registers we're using
  * curr_direction: Was the string equal when we took this path?
  * nodes: A collection of nodes that allows a breadth-first search of the program
  * target: When we find the vulnerable read, we store a tuple of (vuln node, vuln direction, (address to start ROP, read_length))

All the strncmp hook does is try to construct this graph via breadth-first search so that the program
doesn't exit while trying to construct it (since the program terminates after a leaf node completes).
All the read hook does is tries to find the vulnerable read and assigns graph.target if it does.
The read hook will also stop the emulation gracefully.

How do we know if we have a vulnerable read? We can look at ebp, the 2nd argument (buf),
and the 3rd argument (len), and see if buf + len > ebp. If so, there's a fatal overflow.
Otherwise, it's safe. The read hook is listed below, while the strncmp hook is omitted for brevity.

```
def read_hook(ql, graph):
    parms = ql.os.resolve_fcall_params({'fd': INT, 'buf': POINTER, 'len': INT})
    ebp = ql.reg.ebp
    buf = parms['buf']
    buflen = parms['len']
    if buf + buflen > ebp:
        graph.target = (graph.curr_node,graph.curr_direction,(ql.reg.ebp + 4 - buf,buflen))
        ql.stop()
    return buflen
```

## The exploit

This challenge absolutely screams for the use of ret2dlresolve. With that in mind, you might reach
out to pwntools and use its ret2dlresolve capabilities. There are two problems you have to keep in
mind though when doing that.

1) Pwntools ret2dlresolve doesn't handle the symbol version table gracefully. It mostly ignores it.
   This really bites because glibc happens to segfault on high version numbers since it uses that
   to index some sort of table. Ask me about it and I'll tell you how fun it was to stare at GDB,
   the glibc source code (Thank god I at least had that), and the wall as I was banging my head on it.

2) "/bin/sh" is a real classic. Everyone loves "/bin/sh". The typical way to pwn a machine is to
    call system("/bin/sh"). I did something similar, calling execl("/bin/sh", "/bin/sh", 0) which 
    worked locally, but not remotely. I later found out that the server didn't have "/bin/sh", but
    "/bin/bash". This made me pull my hair out for too long. Lesson learned: call other shells 
    beside "/bin/sh" if that doesn't work in the future.

To solve 1), I made a class called CustomRet2dlresolvePayload which behaves like it's pwntools
counterpart, but omits the data_addr argument, instead, defaulting to looking from the start
of .bss, and tries to use an index which happens to resolve to a version of either '0' or '2'.
To do this, I copied pwntools source code and made a few changes. In fact, so few changes, I
can fit the diff file in this README to illustrate.

```
205c205
< class CustomRet2dlresolvePayload(object):
---
> class Ret2dlresolvePayload(object):
226,227c226
<         self.data_addr = self.elf.get_section_by_name(".bss").header.sh_addr & -0x1000 | 0x800
<         #self.data_addr = data_addr if data_addr is not None else self._get_recommended_address()
---
>         self.data_addr = data_addr if data_addr is not None else self._get_recommended_address()
283,289d281
<         old_idx = index
<         while True:
<             ver_addr = self.versym + 2 * index # Elf_HalfWord
<             ver = u16(self.elf.read(ver_addr, 2))
<             if ver == 0 or ver == 2:
<                 break
<             index += 1
```

I did those changes, and it worked locally, but I had problems with remote. I tried spawning a shell,
but ran into 2) and was unaware of the problem. I looked in the hints and saw I could call a function
called "holy_grail", but I randomly had problems with it when calling the server (sometimes it'd work,
most times it wouldn't). After reversing libgrail.so (which I'll describe later), I suspect it's because
pwntools accidentally overwrote the GOT for a function that holy_grail used, but I really don't know.

I toiled for some more until I got help that revealed that I should try other shells like "/bin/bash" instead
of "/bin/sh". It turns out that worked and I was able to get a shell on the server! (yay!).

The shell was a real pain, though (which is part of the challenge). When doing an ls, I found a file called 
"hint.txt" on the server, so I tried to cat it. I didn't get any output. Strange. I suspected that stderr
on the system was redirected to "/dev/null" instead of the socket for ultimate confusion. Therewere other
ways to get what I wanted, though. One way was to use echo "$(<hint.txt)", which worked fine.

More problems came after I saw the hint

**********************************************
Congrats! You we're supposed to find this!

Here's your hint

Your binary was invoked like this

LD_PRELOAD=/lib32/libgrail.so ./bin
**********************************************

I wanted to then read libgrail.so, but the echo trick wouldn't work, since the binary has null bytes.
The way to read that file was to actually use base64, which put it in an easy-to-read format for the
connection so that I could copy and paste it into a file and decode it later.

After I decoded libgrail.so, I saw the "holy_grail" function and saw that it actually did something
very simple, which is to write "DONE\n" to the log file on in the current directory.

This is very easy to do from the shell. The command to pwn is "echo DONE >log".
So I do that 5 times and I get the flag!

flag{Y0u_f1g4t_w311_sir_knig4t_7461834} 
