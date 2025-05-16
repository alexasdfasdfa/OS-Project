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
    for (int sig = SIGMIN; sig <= SIGMAX; sig++) {
        p->signal.sa[sig].sa_sigaction = SIG_DFL; // 默认处理
        sigemptyset(&p->signal.sa[sig].sa_mask); 
        p->signal.sa[sig].sa_restorer = NULL;
    }

    sigemptyset(&p->signal.sigmask);
    sigemptyset(&p->signal.sigpending);

    memset(p->signal.siginfos, 0, sizeof(siginfo_t) * (SIGMAX + 1));
    
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
    struct proc *p = curr_proc();
    if (!p->signal.sigpending) return 0;

    // 遍历所有可能的信号
    for (int sig = SIGMIN; sig <= SIGMAX; sig++) {
        if (sigismember(&p->signal.sigpending, sig) && 
            !sigismember(&p->signal.sigmask, sig)) {
            sigaction_t *sa = &p->signal.sa[sig];
            sigset_t blocked = sa->sa_mask | sigmask(sig); // 当前信号 + sa_mask
            p->signal.sigmask |= blocked;

            if (sa->sa_sigaction == SIG_IGN) {
                sigdelset(&p->signal.sigpending, sig);
            } else if (sa->sa_sigaction == SIG_DFL) {
                setkilled(p,-10-sig);
                sigdelset(&p->signal.sigpending, sig);
            } else {
                struct trapframe *tf = p->trapframe;

                
                struct ucontext uc;
                uc.uc_mcontext.epc = tf->epc;
                // memcpy(uc.uc_mcontext.regs, tf->regs, sizeof(uint64)*31);
                uc.uc_mcontext.regs[0]  = tf->ra;
                uc.uc_mcontext.regs[1]  = tf->sp;
                uc.uc_mcontext.regs[2]  = tf->gp;
                uc.uc_mcontext.regs[3]  = tf->tp;
                uc.uc_mcontext.regs[4]  = tf->t0;
                uc.uc_mcontext.regs[5]  = tf->t1;
                uc.uc_mcontext.regs[6]  = tf->t2;
                uc.uc_mcontext.regs[7]  = tf->s0;
                uc.uc_mcontext.regs[8]  = tf->s1;
                uc.uc_mcontext.regs[9]  = tf->a0;
                uc.uc_mcontext.regs[10] = tf->a1;
                uc.uc_mcontext.regs[11] = tf->a2;
                uc.uc_mcontext.regs[12] = tf->a3;
                uc.uc_mcontext.regs[13] = tf->a4;
                uc.uc_mcontext.regs[14] = tf->a5;
                uc.uc_mcontext.regs[15] = tf->a6;
                uc.uc_mcontext.regs[16] = tf->a7;
                uc.uc_mcontext.regs[17] = tf->s2;
                uc.uc_mcontext.regs[18] = tf->s3;
                uc.uc_mcontext.regs[19] = tf->s4;
                uc.uc_mcontext.regs[20] = tf->s5;
                uc.uc_mcontext.regs[21] = tf->s6;
                uc.uc_mcontext.regs[22] = tf->s7;
                uc.uc_mcontext.regs[23] = tf->s8;
                uc.uc_mcontext.regs[24] = tf->s9;
                uc.uc_mcontext.regs[25] = tf->s10;
                uc.uc_mcontext.regs[26] = tf->s11;
                uc.uc_mcontext.regs[27] = tf->t3;
                uc.uc_mcontext.regs[28] = tf->t4;
                uc.uc_mcontext.regs[29] = tf->t5;
                uc.uc_mcontext.regs[30] = tf->t6;


                uc.uc_sigmask = p->signal.sigmask;

                
                tf->epc = (uint64)sa->sa_sigaction;
                printf("sig is %d\n",sig);
                tf->a0 = sig;
                tf->a1 = (uint64)&p->signal.siginfos[sig];
                tf->a2 = (uint64)&uc;

                
                p->signal.sigmask |= sa->sa_mask;
                sigdelset(&p->signal.sigpending, sig);
            }
            break;
        }
    }
    return 0;
}

// syscall handlers:
//  sys_* functions are called by syscall.c

int sys_sigaction(int signo, const sigaction_t __user *act, sigaction_t __user *oldact) {
    struct proc *p =curr_proc();
    acquire(&p->lock);
    acquire(&p->mm->lock);
    release(&p->lock);
    if(oldact){
        copy_to_user(p->mm,(uint64)oldact,(char*)&p->signal.sa[signo],sizeof(sigaction_t));
    }
    if(act){
        sigaction_t new_act;
        
        copy_from_user(p->mm,(char*)&new_act,(uint64)act,sizeof(sigaction_t));
        memmove(&p->signal.sa[signo],&new_act,sizeof(sigaction_t));
        
        
        
    }
    acquire(&p->lock);
    release(&p->mm->lock);
    release(&p->lock);
    
    return 0;
}

// int sys_sigreturn() {
    // return 0;
// }
int sys_sigreturn() {
    printf("kadsooo\n");
    struct proc *p = curr_proc();
    struct trapframe *tf = p->trapframe;
    struct ucontext *uc = (struct ucontext *)(tf->sp);

    sigset_t blocked = p->signal.sa[tf->a0].sa_mask | sigmask(tf->a0); // 当前信号 + sa_mask
    p->signal.sigmask &= ~blocked;
    printf("%d\n",p->signal.sigmask);

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
    // sigdelset(&p->signal.sigmask, uc->uc_mcontext.regs[10]);
    printf("right now %d\n",tf->a0);



    // 恢复用户栈指针
    tf->sp = (uint64)uc + sizeof(struct ucontext) + sizeof(siginfo_t);
    return 0;
}

int sys_sigprocmask(int how, const sigset_t __user *set, sigset_t __user *oldset) {
    struct proc *p = curr_proc();
    sigset_t new_mask, old_mask;

    old_mask = p->signal.sigmask;

    *oldset=old_mask;

    
    new_mask=*set;
    

    switch (how) {
    case SIG_BLOCK:
        p->signal.sigmask |= new_mask;  
        break;
    case SIG_UNBLOCK:
        p->signal.sigmask &= ~new_mask; 
        break;
    case SIG_SETMASK:
        p->signal.sigmask = new_mask;   
        break;
    }

    return 0;
}

int sys_sigpending(sigset_t __user *set) {
    curr_proc()->signal.sigpending=*set;
    return 0;
}

int sys_sigkill(int pid, int signo, int code) {
    struct proc *p;
    for (int i = 0; i < NPROC; i++)
    {
        p = pool[i];
        if (p->pid==pid)
        {
            p->signal.siginfos[signo].si_code=code;
            sigaddset(&p->signal.sigpending, signo);
            break;
            // sigaction_t *sa =&p->signal.sa[signo];
            // if (sa->sa_sigaction == SIG_IGN) {
            //     sigdelset(&p->signal.sigpending, i);
                
            // } else if (sa->sa_sigaction == SIG_DFL) {
            //     setkilled(p,-10-signo);
            //     sigdelset(&p->signal.sigpending, signo);
                
            // } else {
                
            //     struct trapframe *tf = p->trapframe;
            //     struct ucontext uc;
            //     uc.uc_mcontext.epc = tf->epc;
            //     // memcpy(uc.uc_mcontext.regs, tf->regs, sizeof(uint64)*31);
            //     uc.uc_mcontext.regs[0]  = tf->ra;
            //     uc.uc_mcontext.regs[1]  = tf->sp;
            //     uc.uc_mcontext.regs[2]  = tf->gp;
            //     uc.uc_mcontext.regs[3]  = tf->tp;
            //     uc.uc_mcontext.regs[4]  = tf->t0;
            //     uc.uc_mcontext.regs[5]  = tf->t1;
            //     uc.uc_mcontext.regs[6]  = tf->t2;
            //     uc.uc_mcontext.regs[7]  = tf->s0;
            //     uc.uc_mcontext.regs[8]  = tf->s1;
            //     uc.uc_mcontext.regs[9]  = tf->a0;
            //     uc.uc_mcontext.regs[10] = tf->a1;
            //     uc.uc_mcontext.regs[11] = tf->a2;
            //     uc.uc_mcontext.regs[12] = tf->a3;
            //     uc.uc_mcontext.regs[13] = tf->a4;
            //     uc.uc_mcontext.regs[14] = tf->a5;
            //     uc.uc_mcontext.regs[15] = tf->a6;
            //     uc.uc_mcontext.regs[16] = tf->a7;
            //     uc.uc_mcontext.regs[17] = tf->s2;
            //     uc.uc_mcontext.regs[18] = tf->s3;
            //     uc.uc_mcontext.regs[19] = tf->s4;
            //     uc.uc_mcontext.regs[20] = tf->s5;
            //     uc.uc_mcontext.regs[21] = tf->s6;
            //     uc.uc_mcontext.regs[22] = tf->s7;
            //     uc.uc_mcontext.regs[23] = tf->s8;
            //     uc.uc_mcontext.regs[24] = tf->s9;
            //     uc.uc_mcontext.regs[25] = tf->s10;
            //     uc.uc_mcontext.regs[26] = tf->s11;
            //     uc.uc_mcontext.regs[27] = tf->t3;
            //     uc.uc_mcontext.regs[28] = tf->t4;
            //     uc.uc_mcontext.regs[29] = tf->t5;
            //     uc.uc_mcontext.regs[30] = tf->t6;


            //     uc.uc_sigmask = p->signal.sigmask;

                
            //     tf->epc = (uint64)sa->sa_sigaction;
            //     tf->a0 = signo;
            //     tf->a1 = (uint64)&p->signal.siginfos[signo];
            //     tf->a2 = (uint64)&uc;

                
            //     p->signal.sigmask |= sa->sa_mask;
            //     sigdelset(&p->signal.sigpending, signo);
            // }
            // break;
            
        }
        
    }
    return 0;

}