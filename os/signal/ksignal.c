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
    memmove(child->signal.sa, parent->signal.sa, 
        sizeof(sigaction_t) * (SIGMAX + 1));

    child->signal.sigmask = parent->signal.sigmask;
    sigemptyset(&child->signal.sigpending);
 
    memset(child->signal.siginfos, 0, sizeof(siginfo_t) * (SIGMAX + 1));

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
        if (sigismember(&p->signal.sigpending, sig)){

        
            if(sig == SIGKILL || sig == SIGSTOP || !sigismember(&p->signal.sigmask, sig)) {
                sigaction_t *sa = &p->signal.sa[sig];
            
                if (sig == SIGKILL || sig == SIGSTOP) {
                    setkilled(p, -10 - sig);
                    sigdelset(&p->signal.sigpending, sig);
                    break;
                }

                if (sa->sa_sigaction == SIG_IGN || ( sig==SIGCHLD && sa->sa_sigaction==SIG_DFL)) {
                    sigdelset(&p->signal.sigpending, sig);
                } else if (sa->sa_sigaction == SIG_DFL) {
                    setkilled(p,-10-sig);
                    sigdelset(&p->signal.sigpending, sig);
                } else {
                    struct trapframe *tf = p->trapframe;
    
                    uint64 sp=tf->sp-sizeof(struct ucontext);
                    uint64 info_addr = sp - sizeof(siginfo_t);
                    uint64 uc_addr = info_addr - sizeof(struct ucontext);
                    uc_addr = ROUNDUP_2N(uc_addr, 16);
                    
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
                    tf->a0 = sig;
                    tf->a1 = (uint64)info_addr;
                    tf->a2 = (uint64)&uc_addr;
                    tf->ra=(uint64)sa->sa_restorer;
                    tf->sp=uc_addr;
                    siginfo_t siginfo=p->signal.siginfos[sig];
                    //pass siginfo struct and ucontext to user
                    acquire(&p->mm->lock);
                    copy_to_user(p->mm,uc_addr,(char*)&uc,sizeof(struct ucontext));
                    copy_to_user(p->mm,info_addr,(char*)&siginfo,sizeof(siginfo_t));
                    release(&p->mm->lock);
    
                    
                    sigset_t blocked = sa->sa_mask | sigmask(sig); // 当前信号 + sa_mask
                    p->signal.sigmask |= blocked;
                    sigdelset(&p->signal.sigpending, sig);
                }
                break;
            }
            
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
    struct proc *p = curr_proc();
    struct trapframe *tf = p->trapframe;
    struct ucontext uc;
    acquire(&p->mm->lock);

    // uint64 info_addr=tf->sp;
    // uint64 uc_addr = ROUNDUP_2N(info_addr+sizeof(struct ucontext),16);
    uint64 uc_addr = tf->sp;
    copy_from_user(p->mm, (char*)&uc, uc_addr, sizeof(struct ucontext));
    release(&p->mm->lock);
    
    // struct ucontext *uc = (struct ucontext *)(tf->a2);

    tf->epc = uc.uc_mcontext.epc;
    tf->ra = uc.uc_mcontext.regs[0];
    tf->sp = uc.uc_mcontext.regs[1];
    tf->gp = uc.uc_mcontext.regs[2];
    tf->tp = uc.uc_mcontext.regs[3];
    tf->t0 = uc.uc_mcontext.regs[4];
    tf->t1 = uc.uc_mcontext.regs[5];
    tf->t2 = uc.uc_mcontext.regs[6];
    tf->s0 = uc.uc_mcontext.regs[7];
    tf->s1 = uc.uc_mcontext.regs[8];
    tf->a0 = uc.uc_mcontext.regs[9];
    tf->a1 = uc.uc_mcontext.regs[10];
    tf->a2 = uc.uc_mcontext.regs[11];
    tf->a3 = uc.uc_mcontext.regs[12];
    tf->a4 = uc.uc_mcontext.regs[13];
    tf->a5 = uc.uc_mcontext.regs[14];
    tf->a6 = uc.uc_mcontext.regs[15];
    tf->a7 = uc.uc_mcontext.regs[16];
    tf->s2 = uc.uc_mcontext.regs[17];
    tf->s3 = uc.uc_mcontext.regs[18];
    tf->s4 = uc.uc_mcontext.regs[19];
    tf->s5 = uc.uc_mcontext.regs[20];
    tf->s6 = uc.uc_mcontext.regs[21];
    tf->s7 = uc.uc_mcontext.regs[22];
    tf->s8 = uc.uc_mcontext.regs[23];
    tf->s9 = uc.uc_mcontext.regs[24];
    tf->s10 = uc.uc_mcontext.regs[25];
    tf->s11 = uc.uc_mcontext.regs[26];
    tf->t3=uc.uc_mcontext.regs[27];
    tf->t4=uc.uc_mcontext.regs[28];
    tf->t5=uc.uc_mcontext.regs[29];
    tf->t6 = uc.uc_mcontext.regs[30];  

    p->signal.sigmask = uc.uc_sigmask;
    // sigdelset(&p->signal.sigmask, uc->uc_mcontext.regs[10]);



    // tf->sp = info_addr;
    return 0;
}

int sys_sigprocmask(int how, const sigset_t __user *set, sigset_t __user *oldset) {
    struct proc *p = curr_proc();
    sigset_t new_mask, old_mask;

    acquire(&p->mm->lock);
    if(oldset){
        copy_to_user(p->mm,(uint64)oldset,(char*)&p->signal.sigmask,sizeof(sigset_t));
    }
    if(set){
        copy_from_user(p->mm,(char*)&new_mask,(uint64)set,sizeof(sigset_t));
    }
    release(&p->mm->lock);
    

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
    struct proc *p=curr_proc();
    
    acquire(&p->mm->lock);
    copy_to_user(p->mm,(uint64)set,(char*)&(p->signal.sigpending),sizeof(sigset_t));
    release(&p->mm->lock);
    return 0;
}

int sys_sigkill(int pid, int signo, int code) {

    struct proc *p;
    for (int i = 0; i < NPROC; i++)
    {
        p = pool[i];
        if (p->pid==pid)
        {
            //get the process who send the signal
            struct proc *sender=curr_proc();
            int sender_pid=-1;
            if(sender){
                sender_pid=sender->pid;
            }
            //set siginfo
            //default:si_code=0 si_status=0 addr=0
            p->signal.siginfos[signo].si_code=code;
            p->signal.siginfos[signo].si_status=0;
            p->signal.siginfos[signo].addr=0;
            p->signal.siginfos[signo].si_signo=signo;
            p->signal.siginfos[signo].si_pid=sender_pid;
            sigaddset(&p->signal.sigpending, signo);
            // ...原有代码...
            // p->signal.siginfos[signo].si_code = code;  // 退出代码或信号值
            // p->signal.siginfos[signo].si_signo = signo;
            // p->signal.siginfos[signo].si_pid = sender_pid;
            // ...原有代码...
            break;
            
        }
        
    }
    return 0;

}