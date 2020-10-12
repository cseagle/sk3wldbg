bits 64

%define ARCH_SET_GS 0x1001
%define ARCH_SET_FS 0x1002
%define ARCH_GET_FS 0x1003
%define ARCH_GET_GS 0x1004

%define IA32_EFER 0xc0000080
%define IA32_STAR 0xc0000081
%define IA32_LSTAR 0xc0000082

%define IA32_FS_BASE 0xc0000100
%define IA32_GS_BASE 0xc0000101

%define EINVAL 22

SYSCALL_MAX equ 325+1

times 0xc00 db 0

ENTRY:

   mov rax, 0x4141414141414141    ; replace with desired fs_base
   call set_fs_base

   ; setup syscall handler address
   lea rax, [rel syscall_handler]
   call set_lstar

   ; setup sysret and syscall segments
   mov rax, 0x230010 << 32
   call set_star

   xor rax, rax
   xor rdx, rdx
   xor rcx, rcx
   iretq

set_fs_base:
   mov ecx, IA32_FS_BASE
   call do_wrmsr
   ret

get_fs_base:
   mov ecx, IA32_FS_BASE
   call do_rdmsr
   shl rax, 32
   shrd rax, rdx, 32
   ret

set_gs_base:
   mov ecx, IA32_GS_BASE
   call do_wrmsr
   ret

get_gs_base:
   mov ecx, IA32_GS_BASE
   call do_rdmsr
   shl rax, 32
   shrd rax, rdx, 32
   ret

do_wrmsr:
   mov rdx, rax
   shr rdx, 32
   wrmsr
   ret

do_rdmsr:
   rdmsr
   ret

set_star:
   mov ecx, IA32_STAR
   call do_wrmsr
   ret

set_lstar:               ; syscall addr:
   mov ecx, IA32_LSTAR
   call do_wrmsr
   ret

syscall_handler:
   mov [rel kstack + 0x1000 - 8], rsp
   lea rsp, [rel kstack + 0x1000 - 8]
   push rcx
   push r11
   push rdi
   push rsi
   push rdx
   push r10
   push r8
   push r9
prctl:
   cmp eax, 158    ; arch_prctl
   jnz others
   cmp edi, ARCH_SET_FS
   jnz get_fs
   mov rax, rsi
   call set_fs_base
   jmp success
get_fs:
   cmp edi, ARCH_GET_FS
   jnz set_gs
   call get_fs_base
   mov [rsi], rax
   jmp success
set_gs:
   cmp edi, ARCH_SET_GS
   jnz get_gs
   mov rax, rsi
   call set_gs_base
   jmp success
get_gs:
   cmp edi, ARCH_GET_GS
   jnz einval
   call get_gs_base
   mov [rsi], rax
   jmp success
einval:
   mov eax, EINVAL
   neg rax
   jmp doret
success:
   xor rax, rax
   jmp doret
others:
   ; break here and handle all syscalls via conditional break
   nop
doret:
   pop r9
   pop r8
   pop r10
   pop rdx
   pop rsi
   pop rdi
   pop r11
   pop rcx
   pop rsp
   o64 sysret      ; force 64-bit operad size

align 0x1000
kstack: