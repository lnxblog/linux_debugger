#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <dwarf.h>
#include <libdwarf.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h> 
#include <libgen.h>

#define DEBUG 0
#ifdef ARM 
unsigned int trap=0xe1200070;
#define PC_OFFSET 60
#else
#ifdef INTEL
unsigned char trap=0xcc;
#define PC_OFFSET 128
#endif
#endif
 
void die(char* fmt, ...)
{
    va_list args;
    
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    exit(EXIT_FAILURE);
}

#ifdef INTEL 
typedef struct breakpoint
{
  char name[10];
  Dwarf_Addr addr;
  unsigned char save;
  int count;
  struct breakpoint *nxt;
}bkpt;
#endif

#ifdef ARM
typedef struct breakpoint
{
  char name[10];
  Dwarf_Addr addr;
  unsigned int save;
  int count;
  struct breakpoint *nxt;
}bkpt;
#endif

/* List a function if it's in the given DIE.
*/
void list_func_in_die(Dwarf_Debug dgb, Dwarf_Die the_die,bkpt *curr,int count)
{
  char* die_name = 0;
  const char* tag_name = 0;
  Dwarf_Error err;
  Dwarf_Half tag;
  Dwarf_Attribute* attrs;
  Dwarf_Addr lowpc, highpc;
  Dwarf_Signed attrcount, i;
  int rc = dwarf_diename(the_die, &die_name, &err);

  if (rc == DW_DLV_ERROR)
      die("Error in dwarf_diename\n");
  else if (rc == DW_DLV_NO_ENTRY)
      return;

  if (dwarf_tag(the_die, &tag, &err) != DW_DLV_OK)
      die("Error in dwarf_tag\n");

  /* Only interested in subprogram DIEs here */
  if (tag != DW_TAG_subprogram)
      return;

  /* Grab the DIEs attributes for display */
  if (dwarf_attrlist(the_die, &attrs, &attrcount, &err) != DW_DLV_OK)
      die("Error in dwarf_attlist\n");

  for (i = 0; i < attrcount; ++i) {
      Dwarf_Half attrcode;
      if (dwarf_whatattr(attrs[i], &attrcode, &err) != DW_DLV_OK)
          die("Error in dwarf_whatattr\n");

      /* We only take some of the attributes for display here.
      ** More can be picked with appropriate tag constants.
      */
      if (attrcode == DW_AT_low_pc)
          dwarf_formaddr(attrs[i], &lowpc, 0);
  }

  // store function address in structure
  memcpy(curr->name,die_name,strlen(die_name));
  curr->addr=lowpc;
  curr->count=count;

}


/* List all the functions from the file represented by the given descriptor.
*/
void list_funcs_in_file(Dwarf_Debug dbg,bkpt **curr)
{
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size,tag;
    Dwarf_Error err;
    Dwarf_Die no_die = 0, cu_die, child_die;
    bkpt *prev=NULL;
	  int count=1;

    /* Find compilation unit header */
    if (dwarf_next_cu_header(
                dbg,
                &cu_header_length,
                &version_stamp,
                &abbrev_offset,
                &address_size,
                &next_cu_header,
                &err) == DW_DLV_ERROR)
        die("Error reading DWARF cu header\n");
    
    /* Expect the CU to have a single sibling - a DIE */
    if (dwarf_siblingof(dbg, no_die, &cu_die, &err) == DW_DLV_ERROR)
        die("Error getting sibling of CU\n");

    /* Expect the CU DIE to have children */
    if (dwarf_child(cu_die, &child_die, &err) == DW_DLV_ERROR)
        die("Error getting child of CU DIE\n");

    /* Now go over all children DIEs */
    while (1) {
        int rc;

        if (dwarf_tag(child_die, &tag, &err) != DW_DLV_OK)
            die("Error in dwarf_tag\n");
        if (tag==DW_TAG_subprogram)
        { 
           		*curr=malloc(sizeof(bkpt));
            	list_func_in_die(dbg, child_die,*curr,count);
            	(*curr)->nxt=prev;
            	prev=*curr;
				      count++;
        }

        rc = dwarf_siblingof(dbg, child_die, &child_die, &err);

        if (rc == DW_DLV_ERROR)
            die("Error getting sibling of DIE\n");
        else if (rc == DW_DLV_NO_ENTRY)
            break; /* done */

    }

}

int set_bkpt(int fd,unsigned char trap,bkpt *curr)
{
	pread(fd, &(curr->save), sizeof(curr->save), curr->addr);
	int ret=pwrite(fd, &trap, sizeof(trap), curr->addr);
	if (ret<0)
		perror("error proc write ");
	return ret;
}

int remove_bkpt(int fd,bkpt *bkpt_hit)
{
	int ret=pwrite(fd, &(bkpt_hit->save), sizeof(bkpt_hit->save), bkpt_hit->addr);
	if (ret<0)
		perror("error proc write ");
}

int main(int argc, char** argv)
{
  Dwarf_Debug dbg = 0;
  Dwarf_Error err;
  const char* progname;
  int fd = -1;
  bkpt *start;
  char *filename;
  unsigned char save;
  bkpt *console;
  int bkpt_count=0;

  if (argc < 2) {
    fprintf(stderr, "Expected a program name as argument\n");
    return 1;
  }

  progname = argv[1];
  if ((fd = open(progname, O_RDONLY)) < 0) {
    perror("open");
    return 1;
  }

  filename=basename(progname);


  if (dwarf_init(fd, DW_DLC_READ, 0, 0, &dbg, &err) != DW_DLV_OK) {
    fprintf(stderr, "Failed DWARF initialization\n");
    return 1;
  }

  list_funcs_in_file(dbg,&start);

  if (dwarf_finish(dbg, &err) != DW_DLV_OK) {
    fprintf(stderr, "Failed DWARF finalization\n");
    return 1;
  }

  close(fd);


  pid_t child;
  unsigned long  r7,pc;
  int status;
  char opt[10];

  // Debugging begins..
  child = fork();
  if(child == 0) {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execl(progname, filename,"2\0", NULL);
  }
    else 
	{
		char file[64];
		int ret,fd;
		long long eip;
		sprintf(file, "/proc/%ld/mem", (long)child);

    // wait for child to be stopped by SIGTRAP
		wait(&status);

		#if DEBUG==1
		if (WIFSTOPPED(status))
		{
			printf("signal %d caused stop\n",WSTOPSIG(status));
		}
		#endif


		fd = open(file, O_RDWR);
		if (fd<0)
			perror("error process open ");


		while(1)
		{
		    int num=1;
			int bkpt_opt;
		    printf("Choose breakpoint locations\n");
		    console=start;
			while(1)
			{
				printf("%d. %s\t",console->count,console->name);
				printf("0x%llx\n",console->addr);
				if(console->nxt==NULL)
				    break;
				else
				    console=console->nxt;
			}
		
			scanf("%s",opt);
			if (!strcmp("Q",opt) || !strcmp("q",opt))
				break;

			num=atoi(opt);
			console=start;
			while(1)
			{
				
				if (num==console->count)
					{
						printf("%s chosen\n",console->name);
						set_bkpt(fd,trap,console);
						bkpt_count++;
						break;
					}		
				if(console->nxt==NULL)
				    break;
				else
				    console=console->nxt;
			}
		
	   		
    	}

		while(1)
		{		
			ptrace(PTRACE_CONT, child, NULL, NULL);

			if (bkpt_count>0)
			{
				wait(&status);
				if (WIFSTOPPED(status))
				{
					printf("signal %d caused stop\n",WSTOPSIG(status));
				}
			
				eip = ptrace(PTRACE_PEEKUSER,child,PC_OFFSET,NULL);
				if (eip < 0)
					perror("error ");
				printf("The child is executing %llx\n", eip);
				console=start;
				eip=eip-1;
				while(1)
				{
			
					if (eip==console->addr)
						{
							printf("%s hit\n",console->name);				
							break;
						}		
					if(console->nxt==NULL)
						break;
					else
						console=console->nxt;
				}

				scanf("%s",opt);
				// Q or q quits the breakpoint selection
				if (!strcmp("Q",opt) || !strcmp("q",opt))
					break;
				else if (!strcmp("c",opt))
				{	
					#if DEBUG==1
					pread(fd, &ret, sizeof(ret), console->addr);
					printf("%x\n",ret);
					#endif

					remove_bkpt(fd,console);
			    	ret = ptrace(PTRACE_POKEUSER,child, PC_OFFSET,console->addr);
					if (ret < 0)
						perror("error poke");
					bkpt_count--;

					#if DEBUG==1
					pread(fd, &ret, sizeof(ret), console->addr);
					printf("%x\n",ret);
					#endif
				}
			}
			else
				break;
		}		
	}
    return 0;
}
