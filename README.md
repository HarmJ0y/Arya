#Arya

Arya is a .NET crypter/dropper generator.

It will take a .NET compiled executable or a C# source code file (to compile to a .NET binary using Mono) and then will build a launcher or a dropper for the original exe. 

For the launcher, the binary is base64'd and obfuscated with letter substitution. The launcher wrapper decodes the string and uses .NET reflection to invoke the execution of the original executable.

The dropper will download a base64'ed version of the original executable over http, and then uses reflection to invoke original exection as well.


Arya was created by @harmj0y.

##Software Requirements:

###Linux

Only tested on Kali Linux. 

Dependencies:   Mono (monodoc-browser monodevelop mono-mcs)
                ./setup.sh should kick this all off

