import idaapi

nn = idaapi.netnode("$ kernel")
sc = cpu.rax
cpu.rax = 0
#rather than building a big dict of handlers, this is
#a binary search based on system call #
if sc < 177:
   if sc < 89:
      if sc < 45:
         if sc < 23:
            if sc < 12:
               if sc < 6:
                  if sc < 3:
                     if sc == 0:     #read
                        pass
                     elif sc == 1:   #write
                        pass
                     else:  #2, open
                        msg("open(\"%s\", 0x%x, 0x%x)\n" % (idaapi.get_strlit_contents(cpu.rdi, -1, STRTYPE_C), cpu.rsi, cpu.rdx))
                        cpu.rax = 3
                  elif sc > 3:
                     if sc == 4: #stat
                        pass
                     else:   #5, fstat
                        idaapi.patch_dword(cpu.rsi, 0x4000)
                        idaapi.patch_qword(cpu.rsi + 0x20, 0x1000)
                  else:  #3, close
                     pass
               elif sc > 6:
                  if sc < 9:
                     pass
                  elif sc > 9:
                     if sc == 10:
                        pass   # 10, mprotect
                     else: # 11, munmap
                        msg("munmap(0x%x, 0x%x)\n" % (cpu.rdi, cpu.rsi))
                        rv = idaapi.idc_value_t()
                        idaapi.eval_idc_expr(rv, BADADDR, "sk3wl_munmap(0x%x, 0x%x)" % (cpu.rdi, cpu.rsi))
                        mmt = nn.altval(11)   #KERNEL_MMAP_TOP
                        if mmt == cpu.rdi:
                           nn.altset(11, mmt + cpu.rsi)   #KERNEL_MMAP_TOP
                  else: #mmap
                     msg("mmap(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n" % (cpu.rdi, cpu.rsi, cpu.rdx, cpu.r10, cpu.r8, cpu.r9))
                     mmt = nn.altval(11)   #KERNEL_MMAP_TOP
                     cpu.rax = mmt - cpu.rsi
                     mmt = nn.altset(11, cpu.rax)   #KERNEL_MMAP_TOP
                     rv = idaapi.idc_value_t()
                     idaapi.eval_idc_expr(rv, BADADDR, "sk3wl_mmap(0x%x, 0x%x, 7)" % (cpu.rax, cpu.rsi))
               else: #lstat
                  pass
            elif sc > 12:
               if sc < 17:
                  pass
               elif sc > 17:
                  if sc < 20:
                     if sc == 18: #pwrite64
                        pass
                     else:  #19 readv
                        pass
                  elif sc > 20:
                     if sc == 21: #access
                        cpu.eax = -2  #ENOENT
                        pass
                     else:  #22 pipe
                        pass
                  else: #writev
                     pass
               else: #pread64
                  pass
            else:  #brk
               cb = nn.altval(0)   #KERNEL_BRK
               if cpu.rdi == 0 or cpu.rdi == cb:
                  cpu.rax = cb
               elif cpu.rdi < cb:   #shrinking
                  rv = idaapi.idc_value_t()
                  nb = cpu.rdi & ~0xfff
                  idaapi.eval_idc_expr(rv, BADADDR, "sk3wl_munmap(0x%x, 0x%x)" % (nb, cb - nb))
                  nn.altset(0, nb)   #KERNEL_BRK
                  cpu.rax = nb
               else:  #growing
                  rv = idaapi.idc_value_t()
                  nb = (cpu.rdi + 0xfff) & ~0xfff
                  idaapi.eval_idc_expr(rv, BADADDR, "sk3wl_mmap(0x%x, 0x%x, 7)" % (cb, nb - cb))
                  nn.altset(0, nb)   #KERNEL_BRK
                  cpu.rax = nb
         elif sc > 23:
            if sc < 34:
               pass
            elif sc > 34:
               if sc < 40:
                  if sc < 37:
                     pass
                  elif sc > 37:
                     if sc == 38:  #setitimer
                        pass
                     else: #getpid
                        cpu.rax = nn.altval(1)  #KERNEL_PID
                  else: # alarm
                     pass
               elif sc > 40:
                  pass
               else: # sendfile
                  pass
            else: # pause
               pass
         else:  #select
            pass
      elif sc > 45:
         if sc < 67:
            if sc < 56:
               pass
            elif sc > 56:
               if sc < 61:
                  if sc < 58:
                     pass  #fork, returning 0 
                  elif sc > 58:
                     if sc == 59: #execve
                        msg("execve(\"%s\", ...)\n" % idc.get_strlit_contents(cpu.rdi, -1, STRTYPE_C))
                        cpu.rax = -2   # ENOENT seems reasonable since we can't do this anyway
                        return 1    #actually break
                     else: #60 exit
                        warning("process exited")
                        return 1    #actually break
                  else: #vfork
                     pass
               elif sc > 61:
                  if sc < 64:
                     if sc == 62:  #kill
                        pass
                     else:  #uname
                        for i, ch in enumerate("Linux"):
                           idaapi.patch_byte(cpu.rdi + i, ord(ch))
                        for i, ch in enumerate("ubuntu"):
                           idaapi.patch_byte(cpu.rdi + i + 0x41, ord(ch))
                        for i, ch in enumerate("4.4.0-119-generic"):
                           idaapi.patch_byte(cpu.rdi + i + 0x82, ord(ch))
                        for i, ch in enumerate("#143-Ubuntu SMP Mon Apr 2 16:08:24 UTC 2018"):
                           idaapi.patch_byte(cpu.rdi + i + 0xc3, ord(ch))
                        for i, ch in enumerate("x86_64"):
                           idaapi.patch_byte(cpu.rdi + i + 0x104, ord(ch))
                  elif sc > 64:
                     if sc == 65: #semop
                        pass
                     else:  #semctl
                        pass
                  else:  #semget
                     pass
               else:  #wait4
                  pass
            else:  #clone
               cpu.rax = -1   #make clone attempts fail
         elif sc > 67:
            if sc < 78:
               pass
            elif sc > 78:
               if sc < 83:
                  if sc < 80: #getcwd
                     default_cwd = "/home/user\x00"
                     if cpu.rsi < len(default_cwd):
                        cpu.rax = -34  #ERANGE
                     else:
                        cpu.rax = cpu.rdi
                        for i, ch in enumerate(default_cwd):
                           idaapi.patch_byte(cpu.rdi + i, ord(ch))
                  elif sc > 80:
                     if sc == 81:  #fchdir
                        pass
                     else:   #rename
                        pass 
                  else:  #chdir
                     pass
               elif sc > 83:
                  pass
               else:  #mkdir
                  pass
            else:  #getdents
               pass
         else:  #shmdt
            pass
      else:  #recvfrom
         pass
   elif sc > 89:
      if sc < 133:
         if sc < 111:
            if sc < 100:
               if sc < 94:
                  pass
               elif sc > 94:
                  if sc < 97:
                     pass
                  elif sc > 97:
                     pass
                  else: #getrlimit
                     if cpu.rdi == 3: #RLIMIT_STACK
                        idaapi.patch_qword(cpu.rsi, 0x100000)
                        idaapi.patch_qword(cpu.rsi + 8, 0x100000)
                     #implement others
               else: #lchown
                  pass
            elif sc > 100:
               if sc < 105:
                  if sc < 103:
                     if sc == 101:  #ptrace
                        pass
                     else:   #getuid
                        cpu.rax = nn.altval(3)  #KERNEL_UID
                  elif sc > 103: #getgid
                     cpu.rax = nn.altval(5)  #KERNEL_GID
                  else:  #syslog
                     pass
               elif sc > 105:
                  if sc < 108:
                     if sc == 106:  #setgid
                        pass
                     else:   #geteuid
                        cpu.rax = nn.altval(4)  #KERNEL_EUID
                  elif sc > 108:
                     if sc == 109:  #getpgid
                        pass
                     else:  #110, getppid
                        cpu.rax = nn.altval(2)  #KERNEL_PPID
                  else:  #getegid
                     cpu.rax = nn.altval(6)  #KERNEL_EGID
               else:  #setuid
                  #nn.altset(3, cpu.rax)  #KERNEL_UID
                  pass
            else:  #times
               pass
         elif sc > 111:
            pass
         else:  #getpgrp
            pass
      elif sc > 133:
         pass
      else:  #mknod
         pass
   else:  #readlink
      msg("readlink: %s\n" % idc.get_strlit_contents(cpu.rdi, -1, STRTYPE_C))
      for i, ch in enumerate("/home/user/crack_me"):
         cpu.rax = i
         if i > cpu.rdx:
            break
         idaapi.patch_byte(cpu.rsi + i, ord(ch))
elif sc > 177:
   if sc < 251:
      if sc < 214:
         pass
      elif sc > 214:
         if sc < 232:
            if sc < 223:
               if sc < 218:
                  pass
               elif sc > 218:
                  pass
               else: #set_tid_address
                  nn.altset(8, cpu.rdi)    #KERNEL_TID_ADDRESS
                  cpu.rax = nn.altval(7)   #KERNEL_TID
            elif sc > 223:
               pass
            else: #timer_settime
               pass
         elif sc > 232:
            pass
         else: #epoll_wait
            pass
      else:  #epoll_ctl_old
         pass
   elif sc > 251:
      if sc < 288:
         if sc < 269:
            pass
         elif sc > 269:
            if sc < 278:
               if sc < 273:
                  pass
               elif sc > 273:
                  pass
               else: #set_robust_list
                  nn.altset(9, cpu.rsi) # KERNEL_ROBUST_LIST
                  nn.altset(10, cpu.rdx) # KERNEL_ROBUST_LIST_SIZE
            elif sc > 278:
               pass
            else: #vmsplice
               pass
         else: #faccessat
            pass
      elif sc > 288:
         pass
      else: #accept4
         pass
   else:  #ioprio_set
      pass
else:  #get_kernel_syms
   pass
msg("syscall %d returning 0x%x\n" % (sc, cpu.rax))
return 0
