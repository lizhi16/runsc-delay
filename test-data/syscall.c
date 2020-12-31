#include <sched.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
        if (argc != 3)
        {
                return -1;
        }

        long unsigned int target;
        sscanf(argv[1],"%lx", &target);
        int access;
        sscanf(argv[2],"%d", &access);

        int tmp1 = (unsigned long long)target >> 32;
        tmp1 = tmp1 * 1000 + access;
        int tmp2 = (unsigned long long)target & 0xffffffff;

        setns(tmp1, tmp2);
        //printf("%x, %x\n", tmp1, tmp2);

        return 0;
}
