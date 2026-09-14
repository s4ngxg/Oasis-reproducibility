#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include "host_handoff.h"
#include "vtd_wire.h"
#include "vtd_verify.h"

/* Standalone correctness solver: 256 shares, 128 rows. All inputs must be
 * sealed, host-admitted anonymous descriptors. Metadata is
 * OASISVS1 || context[32] || statement[33] || squarings_u64_be.
 * This is not an untrusted network admission interface or setup attestation. */
static unsigned char *read_public(int fd,size_t maximum,size_t *length) {
  struct stat info;
  int seals=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK;
  if (!host_memory_fd(fd) || (fcntl(fd,F_GET_SEALS)&seals)!=seals ||
      fstat(fd,&info) || info.st_size<=0 || (uint64_t)info.st_size>maximum) return NULL;
  unsigned char *buffer=malloc((size_t)info.st_size);
  if (!buffer) return NULL;
  size_t pos=0;
  while (pos<(size_t)info.st_size) {
    ssize_t amount=pread(fd,buffer+pos,(size_t)info.st_size-pos,(off_t)pos);
    if (amount<0 && errno==EINTR) continue;
    if (amount<=0) { free(buffer); return NULL; }
    pos+=(size_t)amount;
  }
  *length=pos; return buffer;
}

int main(int argc,char **argv) {
  int fd[4],status=1;
  struct rlimit no_core={0,0};
  if (argc!=5 || setrlimit(RLIMIT_CORE,&no_core)) return 2;
  for (unsigned i=0;i<4;i++) {
    char *end; errno=0; unsigned long value=strtoul(argv[i+1],&end,10);
    if (errno || end==argv[i+1] || *end || value<3 || value>1048575) return 2;
    fd[i]=(int)value;
    for (unsigned j=0;j<i;j++) if (fd[i]==fd[j]) return 2;
  }
  struct stat info;
  if (!host_memory_fd(fd[3]) || fstat(fd[3],&info) || info.st_size) return 2;
  size_t ml=0,sl=0,pl=0;
  unsigned char *meta=read_public(fd[0],81,&ml);
  unsigned char *setup=read_public(fd[1],VTD_WIRE_MAX_BYTES,&sl);
  unsigned char *wire=read_public(fd[2],VTD_WIRE_MAX_BYTES,&pl);
  if (!meta || !setup || !wire || ml!=81 || memcmp(meta,"OASISVS1",8)) goto buffers;
  uint64_t t=0,work=0;
  for (unsigned i=73;i<81;i++) t=(t<<8)|meta[i];
  /* Explicit correctness-run work cap, not a security delay calibration. */
  if (!t || t>1000000 || init()!=RLC_OK) goto buffers;
  mpz_t n,g,h,limit,u[256],v[256],du[128],dv[128],z[128],r[128],a[128],b[128];
  ec_t points[256],key;
  bn_t recovered;
  unsigned initialized=0;
  mpz_inits(n,g,h,limit,NULL); ec_null(key); bn_null(recovered);
  for (unsigned i=0;i<256;i++) mpz_inits(u[i],v[i],NULL);
  for (unsigned i=0;i<128;i++) mpz_inits(du[i],dv[i],z[i],r[i],a[i],b[i],NULL);
  RLC_TRY {
    ec_new(key); bn_new(recovered);
    if (meta[40]!=2 && meta[40]!=3) RLC_THROW(ERR_NO_VALID);
    ec_read_bin(key,meta+40,33);
    unsigned char canonical[33];
    if (ec_is_infty(key) || !ec_on_curve(key)) RLC_THROW(ERR_NO_VALID);
    ec_write_bin(canonical,33,key,1);
    if (memcmp(canonical,meta+40,33)) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<256;i++) { ec_null(points[i]); initialized++; ec_new(points[i]); }
    vtd_proof_output decoded={256,128,points,u,v,du,dv,z,r,a,b};
    if (!vtd_setup_decode(n,g,h,limit,setup,sl) ||
        !vtd_proof_decode(&decoded,wire,pl)) RLC_THROW(ERR_NO_VALID);
    vtd_proof_view proof=vtd_commit_view(&decoded);
    if (!vtd_force_open(recovered,&work,t*128,&proof,256,key,meta+8,t,n,g,h,limit))
      RLC_THROW(ERR_NO_VALID);
    unsigned char result[40];
    memcpy(result,"OASISK01",8); bn_write_bin(result+8,32,recovered);
    ssize_t written=pwrite(fd[3],result,sizeof(result),0);
    memzero(result,sizeof(result));
    if (written!=(ssize_t)sizeof(result)) RLC_THROW(ERR_NO_VALID);
    printf("{\"public_input_solver\":true,\"squarings\":%llu}\n",(unsigned long long)work);
    status=0;
  } RLC_CATCH_ANY { status=1; }
  RLC_FINALLY {
    for (unsigned i=0;i<initialized;i++) ec_free(points[i]);
    if (recovered!=NULL) bn_zero(recovered);
    bn_free(recovered); ec_free(key);
  }
  for (unsigned i=0;i<256;i++) mpz_clears(u[i],v[i],NULL);
  for (unsigned i=0;i<128;i++) mpz_clears(du[i],dv[i],z[i],r[i],a[i],b[i],NULL);
  mpz_clears(n,g,h,limit,NULL); clean();
buffers:
  free(meta); free(setup); free(wire);
  if (status && ftruncate(fd[3],0)) return 1;
  return status;
}
