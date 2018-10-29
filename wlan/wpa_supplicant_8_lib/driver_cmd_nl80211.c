/*
 * Driver interaction with extended Linux CFG8021
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 */

#include "hardware_legacy/driver_nl80211.h"
#include "wpa_supplicant_i.h"
#include "config.h"
#ifdef ANDROID
#include "android_drv.h"
#endif

#define WPA_PS_ENABLED		0
#define WPA_PS_DISABLED		1


/* Return type for setBand*/
enum {
	SEND_CHANNEL_CHANGE_EVENT = 0,
	DO_NOT_SEND_CHANNEL_CHANGE_EVENT,
};

typedef struct android_wifi_priv_cmd {
	char *buf;
	int used_len;
	int total_len;
} android_wifi_priv_cmd;

static int drv_errors = 0;

int mrvl_get_power_mode(void *header, int *power_mode)
{

}

int wpa_driver_nl80211_driver_cmd(void *priv, char *cmd, char *buf,
				  size_t buf_len )
{

    return -1;
}

int wpa_driver_set_p2p_noa(void *priv, u8 count, int start, int duration)
{
	return -1;
}

int wpa_driver_get_p2p_noa(void *priv, u8 *buf, size_t len)
{
	return -1;
}

int wpa_driver_set_p2p_ps(void *priv, int legacy_ps, int opp_ps, int ctwindow)
{
	return -1;
}

int wpa_driver_set_ap_wps_p2p_ie(void *priv, const struct wpabuf *beacon,
				 const struct wpabuf *proberesp,
				 const struct wpabuf *assocresp)
{
    return -1;
}
