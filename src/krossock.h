#ifndef KROSSOCK_H
#define KROSSOCK_H

typedef struct krossock_t *krossock_t;

int krossock_eof(krossock_t ks);

krossock_t krossock_connect(const char* addr);
void krossock_disconnect(krossock_t ks);
ssize_t krossock_write(krossock_t ks, const void *buf, size_t nbyte);
ssize_t krossock_read(krossock_t ks, void *buf, size_t nbyte);

ssize_t krossock_send(krossock_t ks, const void *buffer, size_t length, int flags);
ssize_t krossock_recv(krossock_t ks, void *buffer, size_t length, int flags);

#endif
