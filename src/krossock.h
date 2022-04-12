#ifndef KROSSOCK_H
#define KROSSOCK_H

typedef struct krossock_t *krossock_t;

krossock_t krossock_connect(const char* addr);
void krossock_disconnect(krossock_t ks);
int krossock_send(krossock_t ks);
int krossock_recv(krossock_t ks);

#endif
