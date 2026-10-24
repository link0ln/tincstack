#ifndef TINC_DIAG_H
#define TINC_DIAG_H

/*
    diag.h -- In-tunnel diagnostic probes and local diagnostic web server TCP bridge
*/

#include "system.h"
#include "connection.h"
#include "ipv4.h"
#include "net.h"
#include "node.h"

#define DIAG_ICMP_ID 0x5444

extern void diag_init(void);
extern void diag_reload(void);
extern void diag_exit(void);
extern void diag_cleanup_connection(connection_t *c);

extern void diag_set_port(int port, bool from_runtime);
extern int diag_get_port(void);

extern bool diag_my_ipv4(ipv4_t *out);
extern bool diag_is_probe_ipv4(const vpn_packet_t *packet);
extern bool diag_intercept_ipv4(node_t *source, vpn_packet_t *packet);

extern bool control_diag_port_h(connection_t *c, const char *request);
extern bool control_diag_ping_h(connection_t *c, const char *request);

#endif
