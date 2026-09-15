#ifndef TINC_INVITATION_H
#define TINC_INVITATION_H

/*
    invitation.h -- header for invitation.c.
    Copyright (C) 2013-2022 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

int cmd_invite(int argc, char *argv[]);
int cmd_join(int argc, char *argv[]);

// Wait until data can be read from socket, or a timeout occurs.
// true if socket is ready, false on timeout.
bool wait_socket_recv(int fd);

/* Server options carried from inviter to invitee; see invitation.c. Exact
   names only (an allow-list, no prefixes). NULL-terminated. */
extern const char *const PROPAGATED_OPTIONS[];
extern bool invitation_option_propagated(const char *variable);
extern const char *invitation_option_propagated_name(const char *variable);

/* Pure pieces of the join path, exposed for unit and fuzz tests. */
struct yamlconf;
extern bool invitation_yaml_apply(struct yamlconf *yc, const char *net, const char *name, const char *payload, bool allow_unsafe);
extern bool invitation_url_parse(char *url, char **address, char **port, void *hash18, void *cookie18);

#endif
