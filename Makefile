#Set this variable to point to your SDK directory
IDA_SDK=../../

SDKVER=$(shell pwd | grep -o -E "idasdk[0-9]{2,3}" | cut -c 7-)
IDAVER=$(shell pwd | grep -o -E "idasdk[0-9]{2,3}" | cut -c 7- | sed 's/\(.\)\(.\)/\1\.\2/')
IDAVER_MAJOR=$(shell pwd | grep -o -E "idasdk[0-9]{2,3}" | cut -c 7)

PLATFORM=$(shell uname | cut -f 1 -d _)

#Set this variable to the desired name of your compiled plugin
PROC=sk3wldbg_user

ifeq "$(PLATFORM)" "Linux"
IDA=/opt/ida-$(IDAVER)
HAVE_IDA64=$(shell if [ -f $(IDA)/libida64.so ]; then echo -n yes; fi)
PLATFORM_CFLAGS=-D__LINUX__
PLATFORM_LDFLAGS=-shared -s
IDADIR=-L$(IDA)

ifeq "$(IDAVER_MAJOR)" "6"
PLUGIN_EXT32=.plx
PLUGIN_EXT64=.plx64
else
PLUGIN_EXT32=.so
PLUGIN_EXT64=64.so
endif

IDALIB32=-lida
IDALIB64=-lida64

else ifeq "$(PLATFORM)" "Darwin"

IDAHOME=/Applications/IDA Pro $(IDAVER)

ifeq "$(IDAVER_MAJOR)" "6"
IDA=$(shell dirname "`find "$(IDAHOME)" -name idaq | tail -n 1`")
PLUGIN_EXT32=.pmc
PLUGIN_EXT64=.pmc64
else
IDA=$(shell dirname "`find "$(IDAHOME)" -name ida | tail -n 1`")
PLUGIN_EXT32=.dylib
PLUGIN_EXT64=64.dylib
endif

HAVE_IDA64=$(shell find "$(IDA)" -name libida64.dylib -exec echo -n yes \;)
PLATFORM_CFLAGS=-D__MAC__
PLATFORM_LDFLAGS=-dynamiclib
IDADIR=-L"$(IDA)"

IDALIB32=-lida
IDALIB64=-lida64
endif

ifeq "$(IDAVER_MAJOR)" "6"
CFLAGS=-Wextra -Os $(PLATFORM_CFLAGS) -m32 -fPIC
LDFLAGS=$(PLATFORM_LDFLAGS) -m32
else
CFLAGS=-Wextra -Os $(PLATFORM_CFLAGS) -D__X64__ -m64  -fPIC
LDFLAGS=$(PLATFORM_LDFLAGS) -m64
endif

ifeq ($(shell test $(SDKVER) -gt 72; echo $$?),0)
CFLAGS+= -std=c++11
endif

#specify any additional libraries that you may need
EXTRALIBS=-lunicorn

# Destination directory for compiled plugins
OUTDIR=./bin/

#OBJDIR32=x64/
#OBJDIR64=x86/

#list out the object files in your project here
#OBJS32=	$(OBJDIR32)/sk3wldbg.o
#OBJS64=	$(OBJDIR64)/sk3wldbg.o

SRCS=sk3wldbg.cpp sk3wldbg_arm.cpp sk3wldbg_m68k.cpp \
   sk3wldbg_mips.cpp sk3wldbg_plugin.cpp sk3wldbg_ppc.cpp \
   sk3wldbg_sparc.cpp sk3wldbg_x86.cpp loader.cpp mem_mgr.cpp \
   idc_funcs.cpp

BINARY32=$(OUTDIR)$(PROC)$(PLUGIN_EXT32)
BINARY64=$(OUTDIR)$(PROC)$(PLUGIN_EXT64)

ifdef HAVE_IDA64

all: $(OUTDIR) $(BINARY32) $(BINARY64)

clean:
	-@rm *.o
	-@rm $(BINARY32)
	-@rm $(BINARY64)

else

all: $(OUTDIR) $(BINARY32)

clean:
	-@rm *.o
	-@rm $(BINARY32)

endif

$(OUTDIR):
	-@mkdir -p $(OUTDIR)

$(OBJDIR32):
	-@mkdir -p $(OBJDIR32)

$(OBJDIR64):
	-@mkdir -p $(OBJDIR64)

CC=g++
INC=-I$(IDA_SDK)include/ -I./include/

LD=g++

%.o: %.cpp
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

$(BINARY32): $(SRCS)
	$(LD) $(LDFLAGS) -o $@ $(CFLAGS) $(SRCS) $(INC) $(IDADIR) $(IDALIB32) $(EXTRALIBS) 

ifdef HAVE_IDA64

$(BINARY64): $(SRCS)
	$(LD) $(LDFLAGS) -o $@ -D__EA64__ $(CFLAGS) $(SRCS) $(INC) $(IDADIR) $(IDALIB64) $(EXTRALIBS) 

endif

#change sk3wldbg below to the name of your plugin, make sure to add any 
#additional files that your plugin is dependent on
#sk3wldbg.o: sk3wldbg.cpp

