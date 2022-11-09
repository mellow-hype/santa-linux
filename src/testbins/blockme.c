#include <stdio.h>
#include <unistd.h>

int main() {
    int pid = getpid();
    printf("i should be BLOCKED - my PID is %d\n", pid);
    return 0;
}
