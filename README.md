# linux_debugger
A simple debugger developed for the Linux environment based on the Ptrace system call.
Build Steps

On ARM host:
  ### gcc -D ARM debugger.c -o debugger -ldwarf -lelf ###
On INTEL host:
  ### gcc -D INTEL debugger.c -o debugger -ldwarf -lelf ###
 
