#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>

// custom define for our protocol
#define NLPOC 30

// maxlen for symbol targets for probing
#define MAX_SYMBOL_LEN 64
#define MAX_PAYLOAD 1024

// helper function for printing registers from the probe
static void print_regs(struct pt_regs *regs)
{
    // print out registers
    pr_info("REGISTERS:\n\t "
            "rax: 0x%08lx\n\t rbx: 0x%08lx\n\t rcx: 0x%08lx\n\t rdx: 0x%08lx\n\t "
            "rsi: 0x%08lx\n\t rdi: 0x%08lx\n\t r8:  %08lx\n\t r9:  %08lx\n\n",
            regs->ax, regs->bx, regs->cx, regs->dx,
            regs->si, regs->di, regs->r8, regs->r9);
}

