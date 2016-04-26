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

The plugin is dependent on the Unicorn engine. Because IDA is 32-bit, you MUST
have a 32-bit build of the Unicorn library for your IDA platform (Windows,
Linux, OS X).

The plugin is currently based on a patched branch of the Unicorn Engine, available
here: https://github.com/cseagle/Unicorn/tree/ram_addr

```
git clone https://github.com/cseagle/Unicorn.git
cd unicorn
git checkout ram_addr
```

On all platforms you should clone sk3wldbg into your IDA SDK plugins directory so 
that you end up with $IDASDKDIR/plugins/sk3wldbg because the build files all use
relative paths to find the IDA header files.

Compiled binaries will end up in $IDASDKDIR/bin/plugins

### Building on Windows:

Build with Visual Studio C++ 2010 or later using the included solution (.sln)
file. Build targets are included for IDA 32-bit (Release) and IDA 64-bit 
(Release64). These produce sk3wldbg.plw and sk3wldbg.p64 respectively. Note 
that the project configuration assumes that the Unicorn library headers have
been copied into the sk3wldbg directory alongside the solution file (this is
already done in the git repo). If you want to switch to using the actual Unicorn
headers, make sure you update the Visual Studio project settings.

Copy the plugins into your <IDADIR>/plugins directory and Sk3wlDbg will be
listed as an available debugger for all architectures supported by Unicorn.

### Linux / OS X:

Use the include Makefile to build the plugin. You may need to adjust the paths
that get searched to find your IDA installation ("/Applications/IDA Pro 6.9" is
assume on OSX and /opt/ida-6.9 is assumed on Linux). This is required to
successfully link the plugin. Note that the Makefile assumes that the Unicorn
library headers have been copied into the sk3wldbg directory alongside the
plugin source files (this is already done in the git repo). If you want to
switch to using the actual Unicorn headers, make sure you update the Makefile.

## INSTALLATION

Assuming you have installed IDA to $IDADIR, install the plugin by copying the
compiled binaries from $IDASDKDIR/bin/plugins to $IDADIR/plugins (Linux/Windows)
or $IDADIR/idabin/plugins (OS X). Windows users should install the 32-bit Unicorn
dll into $IDADIR as Unicorn1.dll. Linux and OS X users should make sure they
have install the 32-bit Unicorn shared library into an appropriate location on
their respective systems (/usr/local/lib works). This should already be taken
care of if you build Unicorn from source.

### Pre-built binaries:

As an alternative to building the plugin yourself, pre-built binaries for 
IDA 6.9 (Windows, Linux, OS X), including 32-bit versions of the Unicorn 
library are available in the bin directory. Install these per the instructions
above. Pleasae note that the Unicorn library depends on glib-2.0 and libintl.
For Linux users, make sure the 32-bit versions of these libraries are installed 
using your package manager. For OS X users, these libraries may be installed 
with brew or macports. Windows users will need libglib-2.0-0.dll, libintl-8.dll,
libgcc_s_dw2-1.dll, and any other required libraries from Mingw or cygwin
installed into their IDA directory or in a system search path. To install using
msys2/cygwin:

Msys2:

    $ pacman -S make
    $ pacman -S pkg-config
    $ pacman -S mingw-w64-i686-glib2
    $ pacman -S mingw-w64-i686-toolchain

Cygwin:

    $ apt-cyg install make gcc-core pkg-config libpcre-devel zlib-devel libglib2.0-devel

## USING THE PLUGIN

With the plugin installed, open a binary of interest in IDA and select Sk3wlDbg
as your debugger (Debugger/Switch debugger). If Sk3wlDbg does not appear as an 
available debugger, it has either not been installed correctly, the Unicorn
shared library can't be found, or the current processor type is not supported
by the plugin.

No options are currently recognized by the plugin. When you launch the debugger
execution will begin at the current IDA cursor location. **MAKE SURE YOU POSITION
THE CURSOR AT THE INSTRUCTION WHERE YOU WANT EXECUTION TO BEGIN**. You should 
probably also set some breakpoints to make sure you gain control of the debugger
at the earliest opportunity.

The plugin contains very minimalist ELF (ELF64 is coming) and PE/PE32+ loaders to
load the file image into the Unicorn emulator instance. Outside of these formats
the plugin simply copies the contents of your IDA sections into the emulator.
you currently also get a stack and that's about it.

## THINGS THAT WORK (> 0% of the time)

* Basic debugger operations such as step and run
* Breakpoints are just implemented as a set against which the current program counter is compared. Software breakpoints (such as INT 3) are note used.
* IDA's "Take memory snapshot" feature works.

## THINGS THAT DON'T WORK (because they are not yet implemented)

* Conditional breakpoints
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

 
