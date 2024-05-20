#include <seccomp.h> /* libseccomp */
#include <sys/prctl.h> /* prctl */
#include <unistd.h> /* syscalls */
#include <sys/mman.h>

extern void ECDSA_256_sign(unsigned char sig[64], const unsigned char hash[32]);

#ifndef NO_SECCOMP
static volatile unsigned char seccomped = 0;

__attribute__((constructor(0)))
void seccomp_it(void)
{
  /* Defense in depth */
  prctl(PR_SET_NO_NEW_PRIVS, 1);
  prctl(PR_SET_DUMPABLE, 0);

  /* Init the SECCOMP filter */
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL); /* default action: kill */
  /* Go to jail with SECCOMP, filtering only necessary syscalls */
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, 0)); /* read only on stdin */
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 1)); /* write only on stdout */
  /* Allocation related syscalls */
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  /* Enforce non-executable pages */
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 1, SCMP_A2_32(SCMP_CMP_MASKED_EQ, ~(PROT_NONE | PROT_READ | PROT_WRITE)));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);

  /* Load the SECCOMP filter */
  seccomp_load(ctx);

  seccomped = 1;

  return;
}
#endif

int main()
{
  unsigned char sig[64];
  unsigned char hash[32];

#ifndef NO_SECCOMP
  while(!seccomped){
    seccomp_it();
  }
#endif
  
  while (read(0, hash, 32) == 32) {
    ECDSA_256_sign(sig, hash);
    if(write(1, sig, 64) != 64){
        return -1;
    }
  }
  return 0;
}
