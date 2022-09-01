## Introduction

This article deals with the analysis of a common Windows malware that targets users and steals information such as passwords, keystrokes, images from the camera, data saved in the browser, etc.
With the right combination of dynamic analysis and static analysis, it is possible to analyse an exploit and derive very interesting information... perhaps to reuse for our own exploits. :smiling_imp:
 
I analyse a very simple malware by stopping at a static analysis, which therefore does not involve execution of the exploit. The analysis will be done through a disassembler (more on that later) that will allow to 'disassemble' the malware and look inside of it.

Knowledge of assembly language or at least of the language in which the malware is written is usually required, I will provide a brief summary to help close the gap.

## x86 assembly primer (or how a CPU works)

Points to remember:

1. In assembly you are given 8-32 global variables of fixed size to work with called 'registers';
2. Among them there are special registers like the program Counter, which tells the CPU which instruction we're executing next. Every time an instruction is executed, the Program Counter advance;
3. Virtually all computation is expressed in terms of simple operations on registers;
4. What doesn't fit into a register lives in memory;
5. Memory is accessed either with loads of and stores at addresses, as if it were a big array, or through PUSH and POP operations on a stack; 
6. The stack is a LIFO (_Last In First Out_) data structure that stores local variables, memory for functions, control flow, return values;
7. There are 9 main registers in x86 assembly:
   1. EAX --> Accummulator (Arithmetic)
   2. EBX --> Base (Pointer to data)
   3. ECX --> Counter
   4. EDX --> Data (Arithmetic and I/O)
   5. ESI --> Source Index (Pointer to source in stream operations) 
   6. EDI --> Destination Index (Pointer to destination in stream operations)
   7. EBP --> Base pointer (Pointer to Base of Stack)
   8. ESP --> Stack Pointer (Pointer to Top of Stack)
   9. EIP --> Instruction Pointer (Address of next instruction to execute)
8. There a register called the EFLAGS register. The EFLAGS register is the status register that contains the current state of a x86 CPU. The size and meanings of the flag bits are architecture dependent. It usually reflects the result of arithmetic operations as well as information about restrictions placed on the CPU operation at the current time. Some of these flags are important for malware analysis:
    1. CF --> Carry Flag - Set when the result of an operation is too large for the destination operand;
    2. ZF --> Zero Flag - Set when the result of an operation is equal to zero. This one is probably one of the most important flag to look out for, for example an exploit might check if a machine is 64bit and if it is then it will jump to a certain addres, but if it isn't it will jump to a different address;
    3. SF --> Sign Flag - Set if the result of an operation is negative;
    4. TF --> Trap Flag - Set if step by step debugging (one instruction will be executed at a time;
9. Instructions can be divided into three main categories:
    1. Data Transfer (mov,xchg,etc) --> is used to move, transfer, and access data in registers, memory addresses, etc. {example of a mov operation: mov eax, [edx]};
    2. Control Flow (push,call,jmp,etc) --> used to direct the flow of the program -executing different blocks determined by a variable, calling functions, etc. {example of a push operation: push ecx};
    3. Arithmetic/Logic (xor,and,mul,etc) --> used to perform arithmetic, logical bitwise on registers and values. Also used to compare or test two different values. {example of a compare operation: cmp eax,0}. 

Congratulations if you have come this far. I have tried to be as concise and schematic as possible, but bear in mind that assembly is an endless topic.
N.B Note that this is only a brief overview and I have omitted a lot of information (some of it very important to understand assembly in depth) such as the heap, segment registers, etc...you are welcome to delve deeper and write to me to discuss further.

Now to the fun part, shall we?

## Setting Up a Safe Environment

First of all, we need a secure environment that does not affect our everyday devices and data. We will use virtual machines with FlareVM installed for simplicity. Then a whole series of tools for our analysis such as: Process Monitor, Process Hacker and especially dnSpy as debugger.

Since this is not a course or guide on how to secure yourself, I will not explain the process of setting up these tools. I recommend being very careful and documenting yourself before 'playing' with any malware. All your data is at risk, especially if you touch something you do not know well. The same goes for the analysed file, as it is a real malware, I will not provide information on how to obtain it. Google will be of help to you in case you want to investigate further.


## The robber: a .NET Info-Stealer

To put your mind at ease, .NET easily decompiles (unless the code is encrypted but that is a more advanced topic) to source code so there will not be much assembly needed in this analysis. I know I initially said we would only rely on a static analysis but , let's carry out a small, superficial dynamic routine analysis to get the minimum information we need to proceed. BEWARE, IF YOU ARE REPLICATING THIS PROCEDURE AND YOU ARE NOT IN A PROTECTED ENVIRONMENT YOU ARE ABOUT TO INFECT YOUR PC.

### Basic dynamic analysis

Let's open Process Hacker and Process Monitor and detonate the malware. In Process Monitor, it is very useful to filter by "Process Name" of the file we are analysing: 

![image](https://user-images.githubusercontent.com/85311401/187895220-52cbf1b4-1f5c-46aa-87e6-a6d0ea39a4c8.png)

> If we run the file, we can see that the main interface of Process Monitor will be populated with several entries.

![image](https://user-images.githubusercontent.com/85311401/187896148-7f913790-c3ea-4d2b-9372-890c2caf37bd.png)

And already here the amount of information that can be extracted becomes enormous... as you can see there are over 469,000 events within seconds of execution. We can filter the output by operations we find interesting. For example, we might want to see only ReadFile operations rather than Registry value queries. At this level, taking a look at the operations it performs (and with a lot of experience behind you) one can make assumptions (not certainties) about what the malware is doing. As for the sample under analysis, considering that it calls many keys from the registry and tries to read many passwords, one could conclude that it is a password stealer.
Now, if we move to Process Hacker and click on the process, we can open the thread and see if there are any relevant string in memory.

![image](https://user-images.githubusercontent.com/85311401/187898398-244f2490-fec6-4bfb-b4f7-2cea76f3b4fd.png)

> You can see here on Process Hacker some interesting info such as the hypervisor I was using, other processes in place that have been abused in the past [[CVE-2019-1268](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-1268) doesn't ring a bell?], the Process IDs (PIDs) of the various processes.

![image](https://user-images.githubusercontent.com/85311401/187903086-93dc3652-6c8a-4116-b0ed-07a081dcf61a.png)

![image](https://user-images.githubusercontent.com/85311401/187903659-58c27e56-fcd4-404b-b8fa-c6ffd2dc41c1.png)

Analysing a little looks like is stealing informations from the Thunderbird client, Outlook, Google, Firefox local password files, etc.

As with the assembly section here we have just scratched the surface. Much more specific and in-depth analyses are possible. Finally, we come to the central section: the static analysis of malware. 

### Malicious source

For this section we will use a decompiler, I chose [dnSpy](https://github.com/dnSpy/dnSpy). As always, the tool has its peculiarities, but what interests us is the process and the knowledge we gain from it. Once a certain level of experience is reached, the tool becomes interchangeable.
As soon as we load the file into dnSpy we can see that we are presented with a screen with some information about the sample. They concern the description of the file and the title given to it: these are obviously false, to mask what the malware is actually doing.

![image](https://user-images.githubusercontent.com/85311401/187910924-968e3297-054b-4f7a-bd05-0b4d372c9145.png)

From here we have two options: open the drop-down menu on the left, or even better, click on the 'Main' in green marked as the entry point and end up at the point where the malware starts to run. We will take this second route. We can see that there are several interesting libraries in the file structure 'InternetDownloadManager', 'Encryption', etc. The main one is inside "GonnyCam".  

![image](https://user-images.githubusercontent.com/85311401/187912057-3fb23cbf-06e1-4922-af9c-14e1f261eb8e.png)
> The last highlighted library is obfuscated, it may therefore contain something sensitive, we will deal with it later.

From what we see GonnyCam is creating several processes before running.The names of these processes are significant..[GetCurrentWindow](https://www.tabnine.com/code/javascript/functions/electron/BrowserWindow/getCurrentWindow). If we click on the name of the process, we can go and see what it does. Some of them are empty, probably created with undeveloped functions in mind, such as AddToStartup (for persistence purposes probably). 
An interesting process to analyse is `GonnyCam.RecordKeys`. 

![image](https://user-images.githubusercontent.com/85311401/187914194-4c678c8c-85b3-4e10-af83-c5c5207e4a86.png)

We can see that keystrokes instead of a file are saved in memory, to be more stealthy. We then see that with `Send.SendLog` it is sending commands to a Command and Control server and by clicking on `P_Link` we can see the server to which they are sent, which in this case is hiding behind a fake help-desk.

![image](https://user-images.githubusercontent.com/85311401/187914855-c9383505-7916-4a8b-a764-4869004e9119.png)

If we then enter SendLog, we can see that this malware is also slightly inteligent. It sends logs to the command server via post requests and in doing so compares the log values with a defined set. It then checks whether these are passwords, keystrokes, values taken from the clipboard, etc.
Depending on their type, the data are classified and saved differently.

![image](https://user-images.githubusercontent.com/85311401/187916392-ea174d56-77d4-4112-a38f-74a13aa499d5.png)
![image](https://user-images.githubusercontent.com/85311401/187916451-2d7d0c7b-7db0-451d-90e0-af671d176e13.png)

There would be much more to see in each of the individual modules present, but let us move on _Óµ_ the obfuscated one. Here we first need [de4dot](https://github.com/de4dot/de4dot) a deobfuscator and unpacker for .NET to make the code readable. Simply feed de4dot the malware file and it will do the job by creating a new cleaned version that we then open once again with dnSpy. _Óµ_ has now been renamed GClass0 

![image](https://user-images.githubusercontent.com/85311401/187920910-88f5f5d6-456f-4dc1-a8da-f4afd0cb5fce.png)
![image](https://user-images.githubusercontent.com/85311401/187921012-e5bf5a73-5647-4f5e-bcb6-e749585d5842.png)

Here we can see what is called when the malware is executed, process ids, functions etc. It then creates some api's for [KeyBase](https://keybase.io/) which is a messaging app. 
Finally, a part that I will not analyse because I am not an expert enough (I invite others to supplement this article) is the entire encryption and decryption mechanism present in this malware.

![image](https://user-images.githubusercontent.com/85311401/187923014-44df7a69-9ae1-442f-b0d9-986c27797038.png)

## References

* https://www.kernelmode.info/forum/
* https://lookbook.cyberjungles.com/random-research-area/malware-analysis-and-development/malware-development
* https://www.crowdstrike.com/cybersecurity-101/malware/malware-analysis/

## Author

* In THC Telegram group: @F_ederico1