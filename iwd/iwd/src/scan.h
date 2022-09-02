/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2015-2019  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

enum scan_band {
	SCAN_BAND_2_4_GHZ =	0x1,
	SCAN_BAND_5_GHZ =	0x2,
};

enum scan_state {
	SCAN_STATE_NOT_RUNNING,
	SCAN_STATE_PASSIVE,
	SCAN_STATE_ACTIVE,
};

typedef void (*scan_func_t)(struct l_genl_msg *msg, void *user_data);
typedef void (*scan_trigger_func_t)(int, void *);
typedef bool (*scan_notify_func_t)(int err, struct l_queue *bss_list,
					void *userdata);
typedef void (*scan_destroy_func_t)(void *userdata);
typedef void (*scan_freq_set_func_t)(uint32_t freq, void *userdata);

struct scan_freq_set;
struct ie_rsn_info;
struct p2p_probe_resp;
struct p2p_probe_req;
struct p2p_beacon;
struct mmpdu_header;

enum scan_bss_frame_type {
	SCAN_BSS_PROBE_RESP,
	SCAN_BSS_PROBE_REQ,
	SCAN_BSS_BEACON,
};

struct scan_bss {
	uint8_t addr[6];
	uint32_t frequency;
	int32_t signal_strength;
	uint16_t capability;
	uint8_t *rsne;
	uint8_t *wpa;
	uint8_t *osen;
	uint8_t *wsc;		/* Concatenated WSC IEs */
	ssize_t wsc_size;	/* Size of Concatenated WSC IEs */
	enum scan_bss_frame_type source_frame;
	union {
		struct p2p_probe_resp *p2p_probe_resp_info;
		struct p2p_probe_req *p2p_probe_req_info;
		struct p2p_beacon *p2p_beacon_info;
	};
	uint8_t mde[3];
	uint8_t ssid[32];
	uint8_t ssid_len;
	uint8_t supp_rates_ie[10];
	uint8_t *ext_supp_rates_ie;
	uint8_t utilization;
	uint8_t cc[3];
	uint16_t rank;
	uint8_t ht_ie[28];
	uint8_t vht_ie[14];
	uint64_t time_stamp;
	uint8_t hessid[6];
	uint8_t *rc_ie;		/* Roaming consortium IE */
	uint8_t hs20_version;
	uint64_t parent_tsf;
	bool mde_present : 1;
	bool cc_present : 1;
	bool cap_rm_neighbor_report : 1;
	bool has_sup_rates : 1;
	bool ht_capable : 1;
	bool vht_capable : 1;
	bool anqp_capable : 1;
	bool hs20_capable : 1;
};

struct scan_parameters {
	const uint8_t *extra_ie;
	size_t extra_ie_size;
	struct scan_freq_set *freqs;
	uint16_t duration;
	bool flush : 1;
	bool randomize_mac_addr_hint : 1;
	bool no_cck_rates : 1;
	bool duration_mandatory : 1;
	const char *ssid;	/* Used for direct probe request */
};

static inline int scan_bss_addr_cmp(const struct scan_bss *a1,
					const struct scan_bss *a2)
{
	return memcmp(a1->addr, a2->addr, sizeof(a1->addr));
}

static inline bool scan_bss_addr_eq(const struct scan_bss *a1,
					const struct scan_bss *a2)
{
	return !memcmp(a1->addr, a2->addr, sizeof(a1->addr));
}

uint32_t scan_passive(uint64_t wdev_id, struct scan_freq_set *freqs,
			scan_trigger_func_t trigger, scan_notify_func_t notify,
			void *userdata, scan_destroy_func_t destroy);
uint32_t scan_passive_full(uint64_t wdev_id,
			const struct scan_parameters *params,
			scan_trigger_func_t trigger,
			scan_notify_func_t notify, void *userdata,
			scan_destroy_func_t destroy);
uint32_t scan_active(uint64_t wdev_id, uint8_t *extra_ie, size_t extra_ie_size,
			scan_trigger_func_t trigger,
			scan_notify_func_t notify, void *userdata,
			scan_destroy_func_t destroy);
uint32_t scan_active_full(uint64_t wdev_id,
			const struct scan_parameters *params,
			scan_trigger_func_t trigger, scan_notify_func_t notify,
			void *userdata, scan_destroy_func_t destroy);
bool scan_cancel(uint64_t wdev_id, uint32_t id);

void scan_periodic_start(uint64_t wdev_id, scan_trigger_func_t trigger,
				scan_notify_func_t func, void *userdata);
bool scan_periodic_stop(uint64_t wdev_id);

uint64_t scan_get_triggered_time(uint64_t wdev_id, uint32_t id);

void scan_bss_free(struct scan_bss *bss);
int scan_bss_rank_compare(const void *a, const void *b, void *user);

int scan_bss_get_rsn_info(const struct scan_bss *bss, struct ie_rsn_info *info);

struct scan_bss *scan_bss_new_from_probe_req(const struct mmpdu_header *mpdu,
						const uint8_t *body,
						size_t body_len,
						uint32_t frequency, int rssi);

uint8_t scan_freq_to_channel(uint32_t freq, enum scan_band *out_band);
uint32_t scan_channel_to_freq(uint8_t channel, enum scan_band band);
enum scan_band scan_oper_class_to_band(const uint8_t *country,
					uint8_t oper_class);

struct scan_freq_set *scan_freq_set_new(void);
void scan_freq_set_free(struct scan_freq_set *freqs);
bool scan_freq_set_add(struct scan_freq_set *freqs, uint32_t freq);
bool scan_freq_set_contains(struct scan_freq_set *freqs, uint32_t freq);
uint32_t scan_freq_set_get_bands(struct scan_freq_set *freqs);
void scan_freq_set_foreach(const struct scan_freq_set *freqs,
				scan_freq_set_func_t func, void *user_data);
void scan_freq_set_merge(struct scan_freq_set *to,
					const struct scan_freq_set *from);
void scan_freq_set_constrain(struct scan_freq_set *set,
					const struct scan_freq_set *constraint);
bool scan_freq_set_isempty(const struct scan_freq_set *set);

bool scan_wdev_add(uint64_t wdev_id);
bool scan_wdev_remove(uint64_t wdev_id);

bool scan_suspend(uint64_t wdev_id);
void scan_resume(uint64_t wdev_id);
