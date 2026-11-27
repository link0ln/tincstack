#ifndef TINC_TIER_GATE_H
#define TINC_TIER_GATE_H

#include "system.h"

struct connection_t;
struct node_t;

#define TIER_PENALTY_MAX           10000
#define TIER_REUSE_THRESHOLD       500
#define TIER_DROP_PENALTY_BASE     1200
#define TIER_DROP_PENALTY_STEP     400
#define TIER_ANOMALY_PENALTY       350
#define TIER_DECAY_ONLINE_PER_SEC  15
#define TIER_DECAY_OFFLINE_PER_SEC 4
#define TIER_HOLD_BASE_DEFAULT     45
#define TIER_HOLD_MAX              300
#define TIER_CLEAN_RESET_SEC       300
#define TIER_PROBE_INTERVAL_SEC    2
#define TIER_PROBE_TIMEOUT_SEC     3
#define TIER_REDIRECT_GRACE_SEC    10

typedef enum tier_state_t {
	TIER_STATE_DISABLED = 0,
	TIER_STATE_NORMAL = 1,
	TIER_STATE_FALLBACK = 2,
	TIER_STATE_PROBATION = 3,
} tier_state_t;

/* Pure flap-dampening math helpers (exposed for unit tests) */
extern int tier_gate_required_hold_sec(int flap_count, int base_sec);
extern int tier_gate_drop_penalty_delta(int new_flap_count);
extern int tier_gate_decay_penalty(int penalty, time_t elapsed_sec, bool online);
extern bool tier_gate_is_rtt_anomaly(int baseline_rtt_ms, int rtt_ms);
extern bool tier_gate_can_clear_quarantine(int penalty, int stable_sec, int flap_count, int base_sec);

/* Lifecycle & configuration */
extern void tier_gate_init(void);
extern void tier_gate_exit(void);
extern void tier_gate_reload(void);
extern int tier_gate_read_host_tier(const char *name);

/* State queries & metrics */
extern bool tier_gate_is_enabled(void);
extern int tier_gate_active_tier(void);
extern int tier_gate_max_tier(void);
extern int tier_gate_hold_base(void);
extern const char *tier_gate_state_name(void);
extern unsigned int tier_gate_transitions_count(void);
extern unsigned int tier_gate_rejects_count(void);
extern unsigned int tier_gate_redirects_count(void);
extern bool tier_gate_peer_is_healthy(const struct node_t *n);
extern void tier_gate_recompute(bool allow_redirects);
extern void tier_gate_step_second(void);

/* FallbackConnectTo & client fallback helpers */
extern int tier_gate_fallback_rank(const char *name);
extern bool tier_gate_has_fallback_connect_to(void);
extern const char *tier_gate_fallback_name_at(size_t index);
extern void tier_gate_note_peer_rejected(struct node_t *n);
extern time_t tier_gate_peer_retry_after(const struct node_t *n);
extern bool tier_gate_peer_in_cooldown(const struct node_t *n);
extern void tier_gate_clear_peer_cooldown(struct node_t *n);
extern void tier_gate_clear_all_cooldowns(void);
extern void tier_gate_reset_direct_path_state(struct node_t *n);
extern void tier_gate_retry_primary_connectto(void);

/* Admission & connection lifecycle hooks */
extern bool tier_gate_check_admission(struct connection_t *c, struct node_t *n, bool we_dialled);
extern void tier_gate_on_connection_activated(struct connection_t *c, struct node_t *n);
extern void tier_gate_on_peer_disconnected(struct node_t *n);
extern void tier_gate_on_pong(struct connection_t *c);

#endif
