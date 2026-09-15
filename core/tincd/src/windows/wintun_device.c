/*
    wintun_device.c -- Interaction with the WireGuard Wintun driver

    A layer-3 (IP) device backend for tinc on Windows using Wintun
    (https://www.wintun.net/). Unlike the TAP-Win32 backend (L2 ethernet),
    Wintun is IP-only and modern: the adapter is created on connect and
    removed on disconnect, and the IP address / routes are set programmatically
    via iphlpapi instead of by hand.

    Selected at runtime with `DeviceType = wintun` in tinc.conf. Requires
    wintun.dll next to tincd.exe (or on PATH) and Administrator privileges to
    create the adapter.

    tinc internally works on pseudo-ethernet frames in router mode: bytes
    0..11 are a zeroed MAC pair, 12..13 are the ethertype, and the IP packet
    starts at offset 14. Wintun gives/takes bare IP packets, so on read we
    synthesize the ethernet header (ethertype from the IP version nibble) and
    on write we strip it.

    Copyright (C) 2026 — contributed to the link0ln/tinc fork.
    GPL-2.0-or-later (same as the rest of tinc).
*/

#include "../system.h"

#include <windows.h>
#include <winternl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include "../conf.h"
#include "../device.h"
#include "../logger.h"
#include "../names.h"
#include "../net.h"
#include "../route.h"
#include "../utils.h"
#include "../xalloc.h"

/* ---- Wintun API (loaded dynamically from wintun.dll) ----------------------
   Signatures match wintun.h from the official Wintun distribution. We declare
   them here so the fork builds without vendoring the header; the DLL is loaded
   at runtime. */

typedef void *WINTUN_ADAPTER_HANDLE;
typedef void *WINTUN_SESSION_HANDLE;

typedef WINTUN_ADAPTER_HANDLE(WINAPI *WINTUN_CREATE_ADAPTER_FUNC)(
        const WCHAR *Name, const WCHAR *TunnelType, const GUID *RequestedGUID);
typedef WINTUN_ADAPTER_HANDLE(WINAPI *WINTUN_OPEN_ADAPTER_FUNC)(const WCHAR *Name);
typedef void (WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE Adapter);
typedef void (WINAPI *WINTUN_GET_ADAPTER_LUID_FUNC)(WINTUN_ADAPTER_HANDLE Adapter, NET_LUID *Luid);
typedef WINTUN_SESSION_HANDLE(WINAPI *WINTUN_START_SESSION_FUNC)(WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity);
typedef void (WINAPI *WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE Session);
typedef HANDLE(WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)(WINTUN_SESSION_HANDLE Session);
typedef BYTE *(WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session, DWORD *PacketSize);
typedef void (WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session, const BYTE *Packet);
typedef BYTE *(WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session, DWORD PacketSize);
typedef void (WINAPI *WINTUN_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session, const BYTE *Packet);

static WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter;
static WINTUN_OPEN_ADAPTER_FUNC WintunOpenAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC WintunCloseAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC WintunGetAdapterLUID;
static WINTUN_START_SESSION_FUNC WintunStartSession;
static WINTUN_END_SESSION_FUNC WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC WintunSendPacket;

#define WINTUN_RING_CAPACITY (0x400000)  /* 4 MiB ring, per Wintun examples */
#define ETH_HDR 14                       /* synthesized ethernet header size */

static HMODULE wintun_dll = NULL;
static WINTUN_ADAPTER_HANDLE adapter = NULL;
static WINTUN_SESSION_HANDLE session = NULL;
static HANDLE read_wait = NULL;
static io_t device_read_io;

/* `device` and `iface` are the shared globals defined in device.c (declared
   extern in device.h); we reuse them so both backends can be linked together. */
static const char *device_info = "Wintun device";

static bool load_wintun(void) {
	if(wintun_dll) {
		return true;
	}

	wintun_dll = LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);

	if(!wintun_dll) {
		wintun_dll = LoadLibraryW(L"wintun.dll");
	}

	if(!wintun_dll) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not load wintun.dll: %s", winerror(GetLastError()));
		return false;
	}

#define LOAD(sym) do { \
		FARPROC proc_ = GetProcAddress(wintun_dll, #sym); \
		if(!proc_) { logger(DEBUG_ALWAYS, LOG_ERR, "wintun.dll missing %s", #sym); return false; } \
		memcpy(&sym, &proc_, sizeof(sym)); \
	} while(0)

	LOAD(WintunCreateAdapter);
	LOAD(WintunOpenAdapter);
	LOAD(WintunCloseAdapter);
	LOAD(WintunGetAdapterLUID);
	LOAD(WintunStartSession);
	LOAD(WintunEndSession);
	LOAD(WintunGetReadWaitEvent);
	LOAD(WintunReceivePacket);
	LOAD(WintunReleaseReceivePacket);
	LOAD(WintunAllocateSendPacket);
	LOAD(WintunSendPacket);
#undef LOAD

	return true;
}

/* Build the adapter name. We prefer the network name over Interface: Interface
   is a TAP-era concept and reusing it for the Wintun adapter can collide with
   an existing TAP adapter of the same name (Windows then renames the TAP and
   leaves a stale registry entry). The network name is unique per network and
   won't clash with TAP interface names. WintunInterface can override it. */
static void adapter_name_w(WCHAR *out, size_t cch) {
	char *override = NULL;
	const char *name;

	if(get_config_string(lookup_config(&config_tree, "WintunInterface"), &override) && override) {
		name = override;
	} else if(netname) {
		name = netname;
	} else if(iface) {
		name = iface;
	} else {
		name = "tinc";
	}

	MultiByteToWideChar(CP_UTF8, 0, name, -1, out, (int)cch);
	free(override);
}

/* Programmatically assign the adapter's IP from the `WintunAddress` option
   (e.g. "10.210.0.1/24"), via iphlpapi using the adapter LUID — no netsh and
   no manual step. If the option is absent, addressing is left to a tinc-up
   script (classic behaviour). */
static void configure_ip(void) {
	char *spec = NULL;

	if(!get_config_string(lookup_config(&config_tree, "WintunAddress"), &spec) || !spec) {
		logger(DEBUG_ALWAYS, LOG_INFO,
		       "No WintunAddress set; configure the adapter IP via a tinc-up script.");
		return;
	}

	int prefix = -1;
	char *slash = strchr(spec, '/');

	if(slash) {
		*slash = 0;
		prefix = atoi(slash + 1);
	}

	NET_LUID luid;
	WintunGetAdapterLUID(adapter, &luid);

	MIB_UNICASTIPADDRESS_ROW row;
	InitializeUnicastIpAddressEntry(&row);
	row.InterfaceLuid = luid;
	row.DadState = IpDadStatePreferred;

	struct in_addr v4;
	struct in6_addr v6;

	if(inet_pton(AF_INET, spec, &v4) == 1) {
		row.Address.si_family = AF_INET;
		row.Address.Ipv4.sin_family = AF_INET;
		row.Address.Ipv4.sin_addr = v4;
		row.OnLinkPrefixLength = (UINT8)(prefix >= 0 && prefix <= 32 ? prefix : 24);
	} else if(inet_pton(AF_INET6, spec, &v6) == 1) {
		row.Address.si_family = AF_INET6;
		row.Address.Ipv6.sin6_family = AF_INET6;
		row.Address.Ipv6.sin6_addr = v6;
		row.OnLinkPrefixLength = (UINT8)(prefix >= 0 && prefix <= 128 ? prefix : 64);
	} else {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid WintunAddress '%s'", spec);
		free(spec);
		return;
	}

	DWORD r = CreateUnicastIpAddressEntry(&row);

	if(r != NO_ERROR && r != ERROR_OBJECT_ALREADY_EXISTS) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not set adapter IP %s/%d: error %lu",
		       spec, row.OnLinkPrefixLength, (unsigned long)r);
	} else {
		logger(DEBUG_ALWAYS, LOG_INFO, "Adapter IP set to %s/%d", spec, row.OnLinkPrefixLength);
	}

	free(spec);
}

static bool setup_device(void) {
	get_config_string(lookup_config(&config_tree, "Device"), &device);
	get_config_string(lookup_config(&config_tree, "Interface"), &iface);

	if(!iface) {
		iface = xstrdup(netname ? netname : "tinc");
	}

	if(!load_wintun()) {
		return false;
	}

	WCHAR wname[256];
	adapter_name_w(wname, sizeof(wname) / sizeof(wname[0]));

	/* A stable per-network GUID would let the adapter keep its settings across
	   runs; passing NULL lets Wintun allocate one. We create fresh each time so
	   the adapter truly appears on connect and disappears on close. */
	adapter = WintunCreateAdapter(wname, L"tinc", NULL);

	if(!adapter) {
		/* Maybe a stale adapter exists from a crash — try to open & reuse it. */
		adapter = WintunOpenAdapter(wname);
	}

	if(!adapter) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not create Wintun adapter '%s': %s",
		       iface, winerror(GetLastError()));
		return false;
	}

	if(routing_mode != RMODE_ROUTER) {
		logger(DEBUG_ALWAYS, LOG_WARNING,
		       "Wintun is layer-3 only; forcing router mode behaviour. "
		       "Set Mode = router for this network.");
	}

	overwrite_mac = 1;  /* L3: there is no real MAC, tinc fakes the header */
	device_info = "Wintun device";
	logger(DEBUG_ALWAYS, LOG_INFO, "%s adapter '%s' created", device_info, iface);
	return true;
}

static void read_from_wintun(void) {
	for(;;) {
		DWORD size = 0;
		BYTE *ippkt = WintunReceivePacket(session, &size);

		if(!ippkt) {
			/* ERROR_NO_MORE_ITEMS means the ring is drained; anything else is real. */
			DWORD e = GetLastError();

			if(e != ERROR_NO_MORE_ITEMS)
				logger(DEBUG_ALWAYS, LOG_ERR, "Error reading from %s: %s",
				       device_info, winerror(e));

			break;
		}

		if(size + ETH_HDR <= MTU && size >= 1) {
			vpn_packet_t packet;
			packet.offset = 0;
			/* synthesize ethernet header: zero MACs, ethertype from IP version */
			memset(DATA(&packet), 0, 12);
			uint8_t version = ippkt[0] >> 4;

			if(version == 6) {
				DATA(&packet)[12] = 0x86;
				DATA(&packet)[13] = 0xDD;
			} else {
				DATA(&packet)[12] = 0x08;
				DATA(&packet)[13] = 0x00;
			}

			memcpy(DATA(&packet) + ETH_HDR, ippkt, size);
			packet.len = size + ETH_HDR;
			packet.priority = 0;
			route(myself, &packet);
		}

		WintunReleaseReceivePacket(session, ippkt);
	}
}

static void device_handle_read(void *data, int flags) {
	(void)data;
	(void)flags;
	read_from_wintun();
}

static void enable_device(void) {
	logger(DEBUG_ALWAYS, LOG_INFO, "Enabling %s", device_info);

	session = WintunStartSession(adapter, WINTUN_RING_CAPACITY);

	if(!session) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not start Wintun session: %s", winerror(GetLastError()));
		return;
	}

	/* assign the adapter IP automatically (if WintunAddress is configured) */
	configure_ip();

	read_wait = WintunGetReadWaitEvent(session);
	io_add_event(&device_read_io, device_handle_read, NULL, read_wait);
	/* drain anything already queued */
	read_from_wintun();
}

static void disable_device(void) {
	logger(DEBUG_ALWAYS, LOG_INFO, "Disabling %s", device_info);

	if(read_wait) {
		io_del(&device_read_io);
		read_wait = NULL;
	}

	if(session) {
		WintunEndSession(session);
		session = NULL;
	}
}

static void close_device(void) {
	if(session) {
		WintunEndSession(session);
		session = NULL;
	}

	if(adapter) {
		/* This removes the adapter from the system — created on connect,
		   gone on disconnect, exactly as intended. */
		WintunCloseAdapter(adapter);
		adapter = NULL;
	}

	if(wintun_dll) {
		FreeLibrary(wintun_dll);
		wintun_dll = NULL;
	}

	free(device);
	device = NULL;
	free(iface);
	iface = NULL;
	device_info = NULL;
}

static bool read_packet(vpn_packet_t *packet) {
	/* All reads are event-driven via device_handle_read. */
	(void)packet;
	return false;
}

static bool write_packet(vpn_packet_t *packet) {
	if(!session) {
		return false;
	}

	if(packet->len <= ETH_HDR) {
		return true;  /* nothing but the synthesized header */
	}

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Writing packet of %d bytes to %s",
	       packet->len, device_info);

	DWORD ip_len = packet->len - ETH_HDR;
	BYTE *out = WintunAllocateSendPacket(session, ip_len);

	if(!out) {
		DWORD e = GetLastError();

		if(e == ERROR_BUFFER_OVERFLOW) {
			/* ring full — drop, like other backends do under pressure */
			return true;
		}

		logger(DEBUG_ALWAYS, LOG_ERR, "Error allocating Wintun send packet: %s", winerror(e));
		return false;
	}

	memcpy(out, DATA(packet) + ETH_HDR, ip_len);
	WintunSendPacket(session, out);
	return true;
}

const devops_t wintun_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
	.enable = enable_device,
	.disable = disable_device,
};
