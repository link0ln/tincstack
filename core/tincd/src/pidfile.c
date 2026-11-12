#include "system.h"

#ifdef HAVE_WINDOWS
#include <sddl.h>
#endif

#include "pidfile.h"
#include "names.h"

#ifdef HAVE_WINDOWS
static PSECURITY_DESCRIPTOR pidfile_private_sd(void) {
	HANDLE tok;
	PSECURITY_DESCRIPTOR sd = NULL;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
		return NULL;
	}

	TOKEN_ELEVATION elev = {0};
	DWORD n = 0;
	bool elevated = GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &n) && elev.TokenIsElevated;

	if(elevated) {
		ConvertStringSecurityDescriptorToSecurityDescriptorA(
		        "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
		        SDDL_REVISION_1, &sd, NULL);
		CloseHandle(tok);
		return sd;
	}

	n = 0;
	GetTokenInformation(tok, TokenUser, NULL, 0, &n);
	TOKEN_USER *tu = n ? malloc(n) : NULL;

	if(tu && GetTokenInformation(tok, TokenUser, tu, n, &n)) {
		char *sid = NULL;

		if(ConvertSidToStringSidA(tu->User.Sid, &sid)) {
			char sddl[256];
			snprintf(sddl, sizeof(sddl), "D:P(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)", sid);
			ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &sd, NULL);
			LocalFree(sid);
		}
	}

	free(tu);
	CloseHandle(tok);
	return sd;
}
#endif

pidfile_t *read_pidfile(void) {
	FILE *f = fopen(pidfilename, "r");

	if(!f) {
		return NULL;
	}

	pidfile_t *pf = malloc(sizeof(pidfile_t));

	if(!pf) {
		fclose(f);
		return NULL;
	}

	int read = fscanf(f, "%20d %64s %128s port %128s", &pf->pid, pf->cookie, pf->host, pf->port);
	fclose(f);

	if(read != 4) {
		free(pf);
		pf = NULL;
	}

	return pf;
}


bool write_pidfile(const char *controlcookie, const char *address) {
#ifdef HAVE_WINDOWS
	size_t tmplen = strlen(pidfilename) + 5;
	char *tmp = malloc(tmplen);

	if(!tmp) {
		return false;
	}

	snprintf(tmp, tmplen, "%s.tmp", pidfilename);
	DeleteFileA(tmp);

	PSECURITY_DESCRIPTOR sd = pidfile_private_sd();

	if(!sd) {
		free(tmp);
		errno = EACCES;
		return false;
	}

	SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };
	HANDLE h = CreateFileA(tmp, GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	LocalFree(sd);

	if(h == INVALID_HANDLE_VALUE) {
		free(tmp);
		return false;
	}

	int fd = _open_osfhandle((intptr_t)h, _O_WRONLY | _O_TEXT);

	if(fd < 0) {
		CloseHandle(h);
		DeleteFileA(tmp);
		free(tmp);
		return false;
	}

	FILE *f = _fdopen(fd, "w");

	if(!f) {
		_close(fd);
		DeleteFileA(tmp);
		free(tmp);
		return false;
	}

	bool ok = fprintf(f, "%d %s %s\n", (int)getpid(), controlcookie, address) > 0;
	ok = !fflush(f) && ok;
	ok = !fclose(f) && ok;

	if(!ok || !MoveFileExA(tmp, pidfilename, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
		DeleteFileA(tmp);
		free(tmp);
		return false;
	}

	free(tmp);
	return true;
#else
	const mode_t mask = umask(0);
	umask(mask | 077);
	FILE *f = fopen(pidfilename, "w");
	int saved_errno = errno;
	umask(mask);
	errno = saved_errno;

	if(!f) {
		return false;
	}

#ifdef HAVE_FCHMOD
	fchmod(fileno(f), 0600);
#endif
	fprintf(f, "%d %s %s\n", (int)getpid(), controlcookie, address);
	return !fclose(f);
#endif
}
