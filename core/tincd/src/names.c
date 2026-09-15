/*
    names.c -- generate commonly used (file)names
    Copyright (C) 1998-2005 Ivo Timmermans
                  2000-2018 Guus Sliepen <guus@tinc-vpn.org>

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

#include "system.h"

#include "dropin.h"
#include "logger.h"
#include "names.h"
#include "xalloc.h"
#include "yamlconf.h"

char *netname = NULL;
bool netname_defaulted = false; /* YAML mode: netname was not given, make_names() picked it */
char *myname = NULL;
char *confdir = NULL;           /* base configuration directory */
char *confbase = NULL;          /* base configuration directory for this instance of tinc */
bool confbase_given;
char *identname = NULL;         /* program name for syslog */
char *unixsocketname = NULL;    /* UNIX socket location */
char *logfilename = NULL;       /* log file location */
char *pidfilename = NULL;
char *program_name = NULL;

/*
  Set all files and paths according to netname
*/
void make_names(bool daemon) {
#ifdef HAVE_WINDOWS
	HKEY key;
	char installdir[1024] = "";
	DWORD len = sizeof(installdir);
#endif
	confbase_given = confbase;

	/* YAML mode: a *.yaml passed via -c holds all networks. Read the whole
	   config from it (keyed by netname); keep only runtime files (pid, socket,
	   log, cache) in a per-network directory next to the YAML. */
	if(confbase && yamlconf_is_yaml_path(confbase)) {
		yamlconf_path = xstrdup(confbase);
		yamlconf_global = yamlconf_load(yamlconf_path);

		if(!yamlconf_global) {
			if(access(yamlconf_path, F_OK)) {
				logger(DEBUG_ALWAYS, LOG_INFO, "YAML config `%s' does not exist yet; it will be created", yamlconf_path);
			} else {
				logger(DEBUG_ALWAYS, LOG_ERR, "Could not parse YAML config `%s'", yamlconf_path);
			}
		}

		/* No -n given: use the first network in the file, or a default name
		   for a brand-new file, so a bare `-c tinc.yaml` always maps to
		   exactly one network (zero-config first run). */
		if(!netname) {
			const char *first = yamlconf_global ? yamlconf_first_network(yamlconf_global) : NULL;
			netname = xstrdup(first ? first : "tincstack");
			netname_defaulted = true;
		}

		char *dir = xstrdup(yamlconf_path);
		char *sep = NULL;

		for(char *p = dir; *p; p++)
			if(*p == '/' || *p == '\\') {
				sep = p;
			}

		if(sep) {
			*sep = '\0';
		} else {
			free(dir);
			dir = xstrdup(".");
		}

		free(confbase);

		if(netname) {
			xasprintf(&confbase, "%s" SLASH "%s", dir, netname);
		} else {
			xasprintf(&confbase, "%s" SLASH "tinc-run", dir);
		}

		free(dir);
		/* Same mode makedirs() applies to a classic confbase, so later CLI
		   calls do not re-chmod it; secrets live in invitations/ (0700) and
		   the YAML file itself (0600). */
		mkdir(confbase, 0755);
	}

	if(netname && confbase && !yamlconf_path) {
		logger(DEBUG_ALWAYS, LOG_INFO, "Both netname and configuration directory given, using the latter...");
	}

	free(identname);

	if(netname) {
		xasprintf(&identname, "tinc.%s", netname);
	} else {
		identname = xstrdup("tinc");
	}

#ifdef HAVE_WINDOWS

	if(!RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\tinc", 0, KEY_READ, &key)) {
		if(!RegQueryValueEx(key, NULL, 0, 0, (LPBYTE)installdir, &len)) {
			confdir = xstrdup(installdir);

			if(!confbase) {
				if(netname) {
					xasprintf(&confbase, "%s" SLASH "%s", installdir, netname);
				} else {
					xasprintf(&confbase, "%s", installdir);
				}
			}

			if(!logfilename) {
				xasprintf(&logfilename, "%s" SLASH "tinc.log", confbase);
			}
		}

		RegCloseKey(key);
	}

#endif

	if(!confdir) {
		confdir = xstrdup(CONFDIR SLASH "tinc");
	}

	if(!confbase) {
		if(netname) {
			xasprintf(&confbase, CONFDIR SLASH "tinc" SLASH "%s", netname);
		} else {
			xasprintf(&confbase, CONFDIR SLASH "tinc");
		}
	}

#ifdef HAVE_WINDOWS
	(void)daemon;

	if(!logfilename) {
		xasprintf(&logfilename, "%s" SLASH "log", confbase);
	}

	if(!pidfilename) {
		xasprintf(&pidfilename, "%s" SLASH "pid", confbase);
	}

#else
	bool fallback = false;

	if(daemon) {
		if(access(LOCALSTATEDIR, R_OK | W_OK | X_OK)) {
			fallback = true;
		}
	} else {
		char fname[PATH_MAX];
		snprintf(fname, sizeof(fname), LOCALSTATEDIR SLASH "run" SLASH "%s.pid", identname);

		if(access(fname, R_OK)) {
			snprintf(fname, sizeof(fname), "%s" SLASH "pid", confbase);

			if(!access(fname, R_OK)) {
				fallback = true;
			}
		}
	}

	if(!fallback) {
		if(!logfilename) {
			xasprintf(&logfilename, LOCALSTATEDIR SLASH "log" SLASH "%s.log", identname);
		}

		if(!pidfilename) {
			xasprintf(&pidfilename, LOCALSTATEDIR SLASH "run" SLASH "%s.pid", identname);
		}
	} else {
		if(!logfilename) {
			xasprintf(&logfilename, "%s" SLASH "log", confbase);
		}

		if(!pidfilename) {
			if(daemon) {
				logger(DEBUG_ALWAYS, LOG_WARNING, "Could not access " LOCALSTATEDIR SLASH " (%s), storing pid and socket files in %s" SLASH, strerror(errno), confbase);
			}

			xasprintf(&pidfilename, "%s" SLASH "pid", confbase);
		}
	}

#endif

	if(!unixsocketname) {
		size_t len = strlen(pidfilename);
		unixsocketname = xmalloc(len + 8);
		memcpy(unixsocketname, pidfilename, len);

		if(len > 4 && !strcmp(pidfilename + len - 4, ".pid")) {
			strncpy(unixsocketname + len - 4, ".socket", 8);
		} else {
			strncpy(unixsocketname + len, ".socket", 8);
		}
	}
}

void free_names(void) {
	free(identname);
	free(netname);
	free(unixsocketname);
	free(pidfilename);
	free(logfilename);
	free(confbase);
	free(confdir);
	free(myname);

	identname = NULL;
	netname = NULL;
	unixsocketname = NULL;
	pidfilename = NULL;
	logfilename = NULL;
	confbase = NULL;
	confdir = NULL;
	myname = NULL;
}
