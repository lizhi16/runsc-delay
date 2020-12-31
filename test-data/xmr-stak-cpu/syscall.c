#include <sched.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	if (argc != 2) 
	{
		return -1;
	}

        long unsigned int target;
	sscanf(argv[1],"%lx", &target);
	//printf("%lx\n", target);

	//long addr = strtol(argv[1], NULL, 10);
        //printf ("%x\n", addr);

        int tmp1 = (unsigned long long)target >> 32;
        int tmp2 = (unsigned long long)target & 0xffffffff;

        setns(tmp1, tmp2);
        //printf("%x, %x\n", tmp1, tmp2);

        return 0;
}
