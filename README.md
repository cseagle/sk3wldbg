## WARNING: THIS CODE IS VERY RAW AND PROBABLY VERY BUGGY!

## Introduction

This is the Sk3wlDbg plugin for IDA Pro. It's purpose is to provide a front
end for using the Unicorn Engine to emulate machine code that you are viewing
with IDA.

The plugin installs as an IDA debugger which you may select whenever you open
an IDA database containing code supported by Unicorn. Currently supported
architectures include:

* x86
* x86-64
* ARM
* ARM64
* MIPS
* MIPS64
* SPARC
* SPARC64
* M68K

## BUILDING:

The plugin is dependent on the Unicorn engine. IDA versions 6.x and older (pre 7.0)
are buit as 32-bit binaries. If you are using one of these versions of IDA you MUST
have a 32-bit build of the Unicorn library for your IDA platform (Windows,
Linux, OS X). If you are using IDA version 7.0 or later, you MUST have a 64-bit build
of Unicorn.

On all platforms you should clone sk3wldbg into your IDA SDK plugins sub-directory
so that you end up with $IDASDKDIR/plugins/sk3wldbg because the build files all use
relative paths to find the IDA header files.

### Building Unicorn for Linux / OSX

* If building Unicorn for IDA 6.x on Linux use: ./make.sh linux32
* If building Unicorn for IDA 7.x on Linux use: ./make.sh linux64
* If building Unicorn for OS X use: ./make.sh macos-universal

Follow `make.sh` with `make install`

### Build sk3wldbg for Linux / OS X:

Use the include Makefile to build the plugin. You may need to adjust the paths
that get searched to find your IDA installation ("/Applications/IDA Pro N.NN" is
assumed on OSX and /opt/ida-N.NN is assumed on Linux, were N.NN is derived from
the name of your IDA SDK directory eg idasdk695 and should match your IDA version
number). This is required to successfully link the plugin. Note that the Makefile
assumes that the Unicorn library headers have been copied into the sk3wldbg
directory alongside the plugin source files (this is already done in the git repo).
If you want to switch to using the actual Unicorn headers, make sure you update the
Makefile.

$ cd $IDASDKDIR/plugins/sk3wldbg
$ make

Compiled binaries will end up in $IDASDKDIR/plugins/sk3wldbg/bin

```
LINUX
         -------------------------------------------
         |        ida        |        ida64        |
         -------------------------------------------
IDA 6.x  |                   |                     |
 plugin  | sk3wldbg_user.plx | sk3wldbg_user.plx64 |
         -------------------------------------------
IDA 7.x  |                   |                     |
 plugin  | sk3wldbg_user.so  | sk3wldbg_user64.so  |
         -------------------------------------------

OS/X
         ------------------------------------------------
         |        ida           |        ida64          |
         ------------------------------------------------
IDA 6.x  |                      |                       |
 plugin  | sk3wldbg_user.pmc    | sk3wldbg_user.pmc64   |
         ------------------------------------------------
IDA 7.x  |                      |                       |
 plugin  | sk3wldbg_user.dylib  | sk3wldbg_user64.dylib |
         ------------------------------------------------
```

Copy the plugin(s) into your <IDADIR>/plugins directory and Sk3wlDbg will be
listed as an available debugger for all architectures supported by Unicorn.

### Build Unicorn for Windows

Unicorn include unicorn.sln which may be used to build both 32 and 64-bit versions
of Unicorn. The necessary binaires end up in unicorn/msvc/distro/Win32 and 
unicorn/msvc/distro/x86. You will need unicorn.lib and unicorn.dll for your
version of IDA (32 or 64-bit). Copy the appropriate unicorn.lib into your 
sk3wldbg git tree at sk3wldbg/lib/x86 or sk3wldbg/lib/x64.

### Build sk3wldbg for Windows

Build with Visual Studio C++ 2013 or later using the included solution (.sln)
file (sk3wlbdg.sln). Several build targets are available depending on which version
of IDA you are using:

```
         -------------------------------------------
         |        ida        |        ida64        |
         -------------------------------------------
IDA 6.x  |   Release/Win32   |  Release64/Win32    |
 plugin  | sk3wldbg_user.plw | sk3wldbg_user.p64   |
         -------------------------------------------
IDA 7.x  |    Release/x64    |   Release64/x64     |
 plugin  | sk3wldbg_user.dll | sk3wldbg_user64.dll |
         -----------------------------------------
```

Note that the project configuration assumes that the Unicorn library headers have
been copied into the sk3wldbg directory alongside the solution file (this is
already done in the git repo). If you want to switch to using the actual Unicorn
headers, make sure you update the Visual Studio project settings.

Copy the plugin(s) into your <IDADIR>/plugins directory and Sk3wlDbg will be
listed as an available debugger for all architectures supported by Unicorn.

Note that the unicorn dll needs to be found in your PATH or copied into your
IDA installation directory.

## INSTALLATION

Assuming you have installed IDA to $IDADIR, install the plugin by copying the
compiled binaries from $IDASDKDIR/bin/plugins to $IDADIR/plugins (Linux/Windows)
or $IDADIR/idabin/plugins (OS X). Windows users should also copy unicorn.dll into
$IDADIR. Linux and OS X users should make sure they have installed the Unicorn
shared library into an appropriate location on their respective systems
(/usr/local/lib often works). This should already be taken care of if you build
and install Unicorn from source.

### Pre-built binaries:

As an alternative to building the plugin yourself, pre-built binaries for 
IDA 6.95 (Windows, Linux, OS X) are available in the bins directory.
Make sure that you have a suitable Unicorn installed for your platform.

## USING THE PLUGIN

With the plugin installed, open a binary of interest in IDA and select Sk3wlDbg
as your debugger (Debugger/Switch debugger). If Sk3wlDbg does not appear as an 
available debugger, it has either not been installed correctly, the Unicorn
shared library can't be found, or the current processor type is not supported
by the plugin.

No options are currently recognized by the plugin. When you launch the debugger
you will be asked whether you wish to begin execution at the cursor location or
at the program's advertised entry point. You should probably also set some
breakpoints to make sure you gain control of the debugger at some point.

The plugin contains very minimalist ELF32/64 and PE/PE32+ loaders to
load the file image into the Unicorn emulator instance. Outside of these formats
the plugin simply copies the contents of your IDA sections into the emulator.
You currently also get a stack and that's about it.

For ELF64/x86_64, the emulator assumes Linux and sets up a minimal trampoline 
from ring 0 to ring 3 at debug start. Additionaly ring 0 code is installed to 
handle sysenter and provide a sysexit back to ring 3. A conditional breakpoint
can be installed at the tail end of the systenter code (marked by a nop) to 
examine the syscall arguments and, if desired, manipulate the process state
before resuming execution. See linux_kernel_x64.asm and linux_x64_syscall_bpcond.py
for ideas.

Future updates will provide similar ring 0 stubs for ELF32/x86/Linux and 
PE32+/x86_64/Windows.

## THINGS THAT WORK (> 0% of the time)

* Basic debugger operations such as step and run
* Breakpoints are just implemented as a set against which the current program counter is compared.
  Software breakpoints (such as INT 3) are not used.
* IDA's "Take memory snapshot" feature works.
* Conditional breakpoints handled by IDA
* Installed IDC functions allow for mapping additional memory into a Unicorn process
     int64 sk3wl_mmap(int64 base, long size, int perms) where perms are a combination of:
         #define SEGPERM_EXEC  1         ///< Execute
         #define SEGPERM_WRITE 2         ///< Write
         #define SEGPERM_READ  4         ///< Read
     void sk3wl_munmap(int64 base, long size)
     sk3wl_mmap may be used to map new regions of memory into an emulated unicorn process.
     These may be invoked from python via the eval_idc_expr function:
         idaapi.eval_idc_expr(idaapi.idc_value_t(), BADADDR, "sk3wl_mmap(0x41414000, 0x1000, 7)")

## THINGS THAT DON'T WORK (because they are not yet implemented)

* IDA Appcalls
* Exception handling (as in the debugger catching exception that happen in the emulated code like out of bounds memory accesses or illegal instructions)
* Tracing
* Stack traces
* Many other features I have not yet thought of

## OTHER FUTURE WORK

* Extensible hooking interface to hook system calls and other exceptions
* Extensible hooking interface to hook library function calls
* Support for loading required shared libraries into the emulated process
* PEB/TEB and fs segment setup for PE based processes
* Many other features I have not yet thought of

 
