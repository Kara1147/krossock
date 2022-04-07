#include "krossock.h"

#ifndef KROSSOCK_SSL_H
#define KROSSOCK_SSL_H

krossock_t krossock_promote_to_ssl(krossock_t);
krossock_t krossock_init_ssl(krossock_t);
void krossock_destroy_ssl(krossock_t);

#endif
