#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "zmq.h"

static int write_key(const char *directory, const char *name,
                     const char key[41], mode_t mode) {
  char path[1024];
  int descriptor;
  int written;
  int length = snprintf(path, sizeof(path), "%s/%s", directory, name);
  if (length <= 0 || (size_t) length >= sizeof(path)) return -1;
  descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
  if (descriptor < 0) {
    fprintf(stderr, "cannot create %s: %s\n", path, strerror(errno));
    return -1;
  }
  written = dprintf(descriptor, "%s\n", key);
  if (close(descriptor) != 0 || written != 41) return -1;
  return 0;
}

int main(int argc, char **argv) {
  char initiator_public[41];
  char initiator_secret[41];
  char responder_public[41];
  char responder_secret[41];
  if (argc != 2) {
    fprintf(stderr, "usage: %s OUTPUT_DIRECTORY\n", argv[0]);
    return 2;
  }
  if (mkdir(argv[1], 0700) != 0 && errno != EEXIST) {
    perror("mkdir");
    return 1;
  }
  if (zmq_curve_keypair(initiator_public, initiator_secret) != 0 ||
      zmq_curve_keypair(responder_public, responder_secret) != 0 ||
      write_key(argv[1], "initiator_public.key", initiator_public, 0644) != 0 ||
      write_key(argv[1], "initiator_secret.key", initiator_secret, 0600) != 0 ||
      write_key(argv[1], "responder_public.key", responder_public, 0644) != 0 ||
      write_key(argv[1], "responder_secret.key", responder_secret, 0600) != 0) {
    return 1;
  }
  printf("generated=%s\n", argv[1]);
  return 0;
}
