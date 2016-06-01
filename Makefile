#Set this variable to point to your SDK directory
IDA_SDK=../../

PLATFORM=$(shell uname | cut -f 1 -d _)
BIN=$(shell which idaq 2>/dev/null)
ifeq ($(strip $(BIN)),)
BIN=$(shell which idal 2>/dev/null)
ifeq ($(strip $(BIN)),)
BIN=$(HOME)/ida/idal
endif
endif

ifneq "$(PLATFORM)" "MINGW32"
IDA=$(dir $(BIN))
endif

#Set this variable to the desired name of your compiled plugin
PROC=sk3wldbg_user

ifeq "$(PLATFORM)" "MINGW32"
PLATFORM_CFLAGS=-D__NT__ -D__IDP__ -DWIN32 -Os -fno-rtti
PLATFORM_LDFLAGS=-shared -s
LIBDIR32=$(shell find ../../ -type d | grep -E "(lib|lib/)gcc.w32")
ifeq ($(strip $(LIBDIR32)),)
LIBDIR32=../../lib/x86_win_gcc_32
IDALIB32=$(LIBDIR32)/ida.a
endif
LIBDIR64=$(shell find ../../ -type d | grep -E "(lib|lib/)gcc.w64")
ifeq ($(strip $(LIBDIR64)),)
LIBDIR64=../../lib/x86_win_gcc_64
IDALIB64=$(LIBDIR64)/ida.a
endif
PLUGIN_EXT32=.plw
PLUGIN_EXT64=.p64

else ifeq "$(PLATFORM)" "Linux"
BIN=$(shell find /opt -name idaq | tail -n 1)
IDA=$(dir $(BIN))
PLATFORM_CFLAGS=-D__LINUX__
PLATFORM_LDFLAGS=-shared -s
IDADIR=-L$(IDA)
PLUGIN_EXT32=.plx
PLUGIN_EXT64=.plx64

IDALIB32=-lida
IDALIB64=-lida64

else ifeq "$(PLATFORM)" "Darwin"
IDA=$(shell dirname "`find /Applications -name idaq | tail -n 1`")
PLATFORM_CFLAGS=-D__MAC__
PLATFORM_LDFLAGS=-dynamiclib
IDADIR=-L"$(IDA)"
PLUGIN_EXT32=.pmc
PLUGIN_EXT64=.pmc64
IDALIB32=-lida
IDALIB64=-lida64
endif

#Platform specific compiler flags
CFLAGS=-Wextra -Os $(PLATFORM_CFLAGS) -m32

#Platform specific ld flags
LDFLAGS=$(PLATFORM_LDFLAGS) -m32

#specify any additional libraries that you may need
EXTRALIBS=-lunicorn

# Destination directory for compiled plugins
OUTDIR=$(IDA_SDK)bin/plugins/

#OBJDIR32=x64/
#OBJDIR64=x86/

#list out the object files in your project here
#OBJS32=	$(OBJDIR32)/sk3wldbg.o
#OBJS64=	$(OBJDIR64)/sk3wldbg.o

SRCS=sk3wldbg.cpp sk3wldbg_arm.cpp sk3wldbg_m68k.cpp \
   sk3wldbg_mips.cpp sk3wldbg_plugin.cpp sk3wldbg_ppc.cpp \
   sk3wldbg_sparc.cpp sk3wldbg_x86.cpp loader.cpp

BINARY32=$(OUTDIR)$(PROC)$(PLUGIN_EXT32)
BINARY64=$(OUTDIR)$(PROC)$(PLUGIN_EXT64)

all: $(OUTDIR) $(BINARY32) $(BINARY64)

clean:
	-@rm *.o
	-@rm $(BINARY32)
	-@rm $(BINARY64)

$(OUTDIR):
	-@mkdir -p $(OUTDIR)

#$(OBJDIR32):
#	-@mkdir -p $(OBJDIR32)

#$(OBJDIR64):
#	-@mkdir -p $(OBJDIR64)

CC=g++
INC=-I$(IDA_SDK)include/ -I./include/

LD=g++

ifdef X64

%.o: %.cpp
	$(CC) -c $(CFLAGS) -D__X64__ $(INC) $< -o $@

$(BINARY64): $(SRCS)
	$(LD) $(LDFLAGS) -o $@ $(CFLAGS) -D__X64__ $(SRCS) $(INC) $(IDADIR) $(IDALIB64) $(EXTRALIBS) 

else

%.o: %.cpp
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

$(BINARY32): $(SRCS)
	$(LD) $(LDFLAGS) -o $@ $(CFLAGS) $(SRCS) $(INC) $(IDADIR) $(IDALIB32) $(EXTRALIBS) 

$(BINARY64): $(SRCS)
	$(LD) $(LDFLAGS) -o $@ -D__EA64__ $(CFLAGS) $(SRCS) $(INC) $(IDADIR) $(IDALIB64) $(EXTRALIBS) 

endif


#change sk3wldbg below to the name of your plugin, make sure to add any 
#additional files that your plugin is dependent on
sk3wldbg.o: sk3wldbg.cpp

