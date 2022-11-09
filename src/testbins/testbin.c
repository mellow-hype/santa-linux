#include <stdio.h>
#include <unistd.h>
#include <linux/fs.h>
#include <linux/stat.h>

int main() {
    int pid = getpid();
    printf("- my PID is %d\n", pid);
    return 0;
}
