#include "krossock.h"

#ifndef KROSSOCK_SSL_H
#define KROSSOCK_SSL_H

krossock_t krossock_connect_ssl(const char* addr);
void krossock_disconnect_ssl(krossock_t ks);
int krossock_send_ssl(krossock_t ks);
int krossock_recv_ssl(krossock_t ks);

#endif
