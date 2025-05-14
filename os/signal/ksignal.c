#include "ksignal.h"

#include <defs.h>
#include <proc.h>
#include <trap.h>

/**
 * @brief init the signal struct inside a PCB.
 * 
 * @param p 
 * @return int 
 */
int siginit(struct proc *p) {
    // init p->signal
    return 0;
}

int siginit_fork(struct proc *parent, struct proc *child) {
    // copy parent's sigactions and signal mask
    // but clear all pending signals
    return 0;
}

int siginit_exec(struct proc *p) {
    // inherit signal mask and pending signals.
    // but reset all sigactions (except ignored) to default.
    return 0;
}

int do_signal(void) {
    assert(!intr_get());
    struct proc *p = curr_proc();
    if (p->signal.sigpending)
    {
        if (!p->signal.sigmask)
        {
            SIG_DFL;
        }
        
    }
    

    return 0;
}

// syscall handlers:
//  sys_* functions are called by syscall.c

int sys_sigaction(int signo, const sigaction_t __user *act, sigaction_t __user *oldact) {
    oldact->sa_sigaction = act->sa_sigaction;
    struct proc *p =curr_proc();
    memmove(&p->signal.sa[signo], act->sa_sigaction, sizeof(sigaction_t));
    return 0;
}

// int sys_sigreturn() {
    // return 0;
// }
int sys_sigreturn() {
    struct proc *p = curr_proc();
    struct trapframe *tf = p->trapframe;
    struct ucontext *uc = (struct ucontext *)(tf->sp);

    // 恢复寄存器和sigmask
    tf->epc = uc->uc_mcontext.epc;
    // memcpy(tf->regs, uc->uc_mcontext.regs, sizeof(uint64) * 31);
    // tf->kernel_satp = uc->
    tf->ra = uc->uc_mcontext.regs[0];
    tf->sp = uc->uc_mcontext.regs[1];
    tf->gp = uc->uc_mcontext.regs[2];
    tf->tp = uc->uc_mcontext.regs[3];
    tf->t0 = uc->uc_mcontext.regs[4];
    tf->t1 = uc->uc_mcontext.regs[5];
    tf->t2 = uc->uc_mcontext.regs[6];
    tf->s0 = uc->uc_mcontext.regs[7];
    tf->s1 = uc->uc_mcontext.regs[8];
    tf->a0 = uc->uc_mcontext.regs[9];
    tf->a1 = uc->uc_mcontext.regs[10];
    tf->a2 = uc->uc_mcontext.regs[11];
    tf->a3 = uc->uc_mcontext.regs[12];
    tf->a4 = uc->uc_mcontext.regs[13];
    tf->a5 = uc->uc_mcontext.regs[14];
    tf->a6 = uc->uc_mcontext.regs[15];
    tf->a7 = uc->uc_mcontext.regs[16];
    tf->s2 = uc->uc_mcontext.regs[17];
    tf->s3 = uc->uc_mcontext.regs[18];
    tf->s4 = uc->uc_mcontext.regs[19];
    tf->s5 = uc->uc_mcontext.regs[20];
    tf->s6 = uc->uc_mcontext.regs[21];
    tf->s7 = uc->uc_mcontext.regs[22];
    tf->s8 = uc->uc_mcontext.regs[23];
    tf->s9 = uc->uc_mcontext.regs[24];
    tf->s10 = uc->uc_mcontext.regs[25];
    tf->s11 = uc->uc_mcontext.regs[26];
    tf->t3 = uc->uc_mcontext.regs[27];
    tf->t4 = uc->uc_mcontext.regs[28];
    tf->t5 = uc->uc_mcontext.regs[29];
    tf->t6 = uc->uc_mcontext.regs[3];    












































    
    
    p->signal.sigmask = uc->uc_sigmask;

    // 恢复用户栈指针
    tf->sp = (uint64)uc + sizeof(struct ucontext) + sizeof(siginfo_t);
    return 0;
}

int sys_sigprocmask(int how, const sigset_t __user *set, sigset_t __user *oldset) {
    return 0;
}

int sys_sigpending(sigset_t __user *set) {
    curr_proc()->signal.sigpending=set;
    return 0;
}

int sys_sigkill(int pid, int signo, int code) {
    struct proc *p;
    for (int i = 0; i < NPROC; i++)
    {
        p = pool[i];
        if (p->pid==pid)
        {
            break;
        }
        
    }
    setkilled(p,code);
    p->signal.siginfos[signo].si_code=code;
    // p->signal.siginfos->si_signo=signo;
    return 0;
}