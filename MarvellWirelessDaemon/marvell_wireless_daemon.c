/*
* All Rights Reserved
*
* MARVELL CONFIDENTIAL
* Copyright 2008 ~ 2010 Marvell International Ltd All Rights Reserved.
* The source code contained or described herein and all documents related to
* the source code ("Material") are owned by Marvell International Ltd or its
* suppliers or licensors. Title to the Material remains with Marvell International Ltd
* or its suppliers and licensors. The Material contains trade secrets and
* proprietary and confidential information of Marvell or its suppliers and
* licensors. The Material is protected by worldwide copyright and trade secret
* laws and treaty provisions. No part of the Material may be used, copied,
* reproduced, modified, published, uploaded, posted, transmitted, distributed,
* or disclosed in any way without Marvell's prior express written permission.
*
* No license under any patent, copyright, trade secret or other intellectual
* property right is granted to or conferred upon you by disclosure or delivery
* of the Materials, either expressly, by implication, inducement, estoppel or
* otherwise. Any license under such intellectual property rights must be
* express and approved by Marvell in writing.
*
*/
#define LOG_TAG "marvellWirelessDaemon"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <utils/Log.h>

#include <cutils/log.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <cutils/properties.h>

#include <sys/prctl.h>
#include <sys/capability.h>
#include <linux/capability.h>
#include <private/android_filesystem_config.h>
#include <dirent.h>

#include "marvell_wireless_daemon.h"


#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef HCI_DEV_ID
#define HCI_DEV_ID 0
#endif

#define HCID_START_DELAY_SEC   1
#define HCID_STOP_DELAY_USEC 500000
#define HCIATTACH_STOP_DELAY_SEC 1
#define FM_ENABLE_DELAY_SEC  3
#define FW_STATE_NORMAL 0
#define FW_STATE_HUNG   1
#define MRVL_WL_RECOVER_DISABLED 0


/** BIT value */
#define MBIT(x)    (1 << (x))
#define DRV_MODE_STA       MBIT(0)
#define DRV_MODE_UAP       MBIT(1)
#define DRV_MODE_WIFIDIRECT       MBIT(2)

#define STA_WEXT_MASK        MBIT(0)
#define UAP_WEXT_MASK        MBIT(1)
#define STA_CFG80211_MASK    MBIT(2)
#define UAP_CFG80211_MASK    MBIT(3)
#define info(fmt, ...)  ALOGI ("%s(L%d): " fmt,__FUNCTION__, __LINE__,  ## __VA_ARGS__)
#define debug(fmt, ...) ALOGD ("%s(L%d): " fmt,__FUNCTION__, __LINE__,  ## __VA_ARGS__)
#define warn(fmt, ...) ALOGW ("## WARNING : %s(L%d): " fmt "##",__FUNCTION__, __LINE__, ## __VA_ARGS__)
#define error(fmt, ...) ALOGE ("## ERROR : %s(L%d): " fmt "##",__FUNCTION__, __LINE__, ## __VA_ARGS__)
#define asrt(s) if(!(s)) ALOGE ("## %s assert %s failed at line:%d ##",__FUNCTION__, #s, __LINE__)

//SD8XXX power state
union POWER_SD8XXX
{
    unsigned int on; // FALSE, means off, others means ON
    struct
    {
        unsigned int wifi_on:1;  //TRUE means on, FALSE means OFF
        unsigned int bt_on:1;
        unsigned int fm_on:1;
        unsigned int nfc_on:1;
    }type;
} power_sd8xxx;

//Static paths and args
static const char* WIFI_DRIVER_MODULE_8777_REGION_ALPHA_PARAM  = "/sys/module/sd8777/parameters/reg_alpha2";
static const char* WIFI_DRIVER_MODULE_8777_MAC_ADDR_PARAM      = "/sys/module/sd8777/parameters/mac_addr";
static const char* WIFI_DRIVER_MODULE_8777_MFG_MODE_PARAM      = "/sys/module/sd8777/parameters/mfg_mode";
static const char* WIFI_DRIVER_MODULE_8777_CFG80211_WEXT_PARAM = "/sys/module/sd8777/parameters/cfg80211_wext";
static const char* WIFI_DRIVER_MODULE_8777_AUTO_DS_PARAM       = "/sys/module/sd8777/parameters/auto_ds";
static const char* WIFI_DRIVER_MODULE_8777_PS_MODE_PARAM       = "/sys/module/sd8777/parameters/ps_mode";
static const char* WIFI_DRIVER_MODULE_8777_HW_TEST_PARAM       = "/sys/module/sd8777/parameters/hw_test";

static const char* WIFI_DRIVER_MODULE_REGION_ALPHA_CONF = "/system/etc/firmware/mrvl/reg_alpha2";
static const char* WIFI_DRIVER_MODULE_MAC_INFO          = "/efs/wifi/.mac.info";
static const char* WIFI_DRIVER_MODULE_PSM_INFO          = "/data/.psm.info";

static const char* WIFI_DRIVER_MODULE_INIT_CFG_PATH = "mrvl/wifi_init_cfg.conf";
static const char* WIFI_DRIVER_MODULE_INIT_CFG_STORE_PATH = "/data/misc/wireless/wifi_init_cfg.conf";

static const char* WIFI_DRIVER_MODULE_CAL_DATA_CFG_PATH = "mrvl/wifi_cal_data.conf";
static const char* WIFI_DRIVER_MODULE_CAL_DATA_CFG_STORE_PATH = "/system/etc/firmware/mrvl/wifi_cal_data.conf";

static const char* BT_DRIVER_MODULE_8777_BT_MAC_PARAM      = "/sys/module/mbt8777/parameters/bt_mac";

static const char* BT_DRIVER_MODULE_INIT_CFG_PATH = "mrvl/bt_init_cfg.conf";
static const char* BT_DRIVER_MODULE_INIT_CFG_STORE_PATH = "/data/misc/wireless/bt_init_cfg.conf";
static const char* BT_DRIVER_MODULE_BT_ADDR = "/efs/bluetooth/bt_addr";

static const char* WIRELESS_UNIX_SOCKET_DIR = "/data/misc/wireless/socket_daemon";

static const char DRIVER_PROP_NAME[]    = "wlan.driver.status";

static const char* RFKILL_SD8X_PATH = "/sys/class/rfkill/rfkill0/state";

static const char* WIFI_DRIVER_IFAC_NAME = "/sys/class/net/wlan0";
static const char* BT_DRIVER_DEV_NAME    = "/dev/mbtchar0";
static const char* FM_DRIVER_DEV_NAME    = "/dev/mfmchar0";
static const char* NFC_DRIVER_DEV_NAME   = "/dev/mnfcchar0";

#define WIRELESS_POWER_SET_PATH "/sys/devices/platform/sd8x-rfkill/pwr_ctrl"
#define SDIO_DEVICE_PATH        "/sys/bus/sdio/devices/mmc2:0001:1/device"
#define MRVL_PROP_WL_RECOVERY   "persist.sys.mrvl_wl_recovery"

enum
{
    WIFI_DRIVER_IFAC_INDEX,
    BT_DRIVER_DEV_INDEX,
    FM_DRIVER_DEV_INDEX,
    NFC_DRIVER_DEV_INDEX
};

enum
{
	TYPE_SD8777,
	TYPE_SD8787,
	TYPE_SD8887,
	TYPE_SD8897,
	TYPE_SD8xxx,
};

enum
{
	CARD_ID_SD8777 = 0x9131,
	CARD_ID_SD8787 = 0x9119,
	CARD_ID_SD8887 = 0x9135,
	CARD_ID_SD8897 = 0x912D,
	CARD_ID_SD8xxx = 0xFFFF,
};

struct sdio_type_t
{
	int index;
	int id;
	const char* name;
} sdio_types[] = {
	{TYPE_SD8777, CARD_ID_SD8777, "8777"},
	{TYPE_SD8787, CARD_ID_SD8787, "8787"},
	{TYPE_SD8887, CARD_ID_SD8887, "8887"},
	{TYPE_SD8897, CARD_ID_SD8897, "8897"},
	{TYPE_SD8xxx, CARD_ID_SD8xxx, "8xxx"},
};

struct driver_debug_t
{
	int index;
	const char *status;
	const char *config;
} drivers_debug[] = {
	{0, "/proc/mwlan/wlan0/info"    , "/proc/mwlan/wlan0/debug"   },
	{1, "/proc/mbt/mbtchar0/status" , "/proc/mbt/mbtchar0/config" },
	{2, "/proc/mbt/mfmchar0/status" , "/proc/mbt/mfmchar0/config" },
	{3, "/proc/mbt/mnfcchar0/status", "/proc/mbt/mnfcchar0/config"},
};

static const char *android_persist_prop[] = {
	"persist.sys.wifi.driver.version",
	"persist.sys.bt.driver.version",
	"persist.sys.fm.driver.version",
	"persist.sys.nfc.driver.version",
};


static int flag_exit = 0;
static int debug = 1;

#define RANDOM(x) (rand()%x)
#define MAC_ADDR_LENGTH 12
#define VENDOR_PREFIX_LENGTH 6
#define FMT_MAC_ADDR_LEN (MAC_ADDR_LENGTH+5)
//                              u+r,   u+w,  u+x,  g+r,  g+w,  g+x,  u+r,  u+w,  u+x
unsigned short right_masks[] = {0x100, 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};

unsigned char hex_char[]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
//Marvell MAC prefix assigned by IEEE: 00:50:43
const char *vendor_prefix = "00:50:43:00:00:00";
const char* wifi_mac_path = "/NVM/wifi_addr";
const char* bt_mac_path = "/NVM/bt_addr";
char fmt_mac_addr[FMT_MAC_ADDR_LEN+1];
const char *rights = "rwxrwxrwx";

void android_set_aid_and_cap()
{
    int ret = -1;
    prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

    gid_t groups[] = {AID_BLUETOOTH, AID_WIFI, AID_NET_BT_ADMIN, AID_NET_BT, AID_INET, AID_NET_RAW, AID_NET_ADMIN};
    if ((ret = setgroups(sizeof(groups)/sizeof(groups[0]), groups)) != 0){
        ALOGE("setgroups failed, ret:%d, strerror:%s", ret, strerror(errno));
        return;
    }

    if(setgid(AID_SYSTEM) != 0){
        ALOGE("setgid failed, ret:%d, strerror:%s", ret, strerror(errno));
        return;
    }

    if ((ret = setuid(AID_SYSTEM)) != 0){
        ALOGE("setuid failed, ret:%d, strerror:%s", ret, strerror(errno));
        return;
    }

    struct __user_cap_header_struct header;
    struct __user_cap_data_struct cap;
    header.version = _LINUX_CAPABILITY_VERSION;
    header.pid = 0;

    cap.effective = cap.permitted = 1 << CAP_NET_RAW |
    1 << CAP_NET_ADMIN |
    1 << CAP_NET_BIND_SERVICE |
    1 << CAP_SYS_MODULE |
    1 << CAP_IPC_LOCK |
    1 << CAP_KILL;

    cap.inheritable = 0;
    if ((ret = capset(&header, &cap)) != 0){
        ALOGE("capset failed, ret:%d, strerror:%s", ret, strerror(errno));
        return;
    }
    return;
}

int write_param(const char* filepath, const char* param)
{
    int fd;
    int len;
    int sent;

    if( filepath )
    {
        fd = TEMP_FAILURE_RETRY(open(filepath, O_WRONLY));
        if( fd < 0 )
        {
            ALOGE("Failed to open: %s (%s) %d", filepath, strerror(errno), errno);
            return -1;
        }

        len = strlen(param) + 1;
        do
        {
            sent = write(fd, param, len);
            if( sent != -1 )
                break;
        }
        while( errno == EINTR );
        close(fd);
        if( sent != len )
        {
            ALOGE("Failed to write param: %s (%s) %d", param, strerror(errno), errno);
            return -1;
        }
    }
    return 0;
}

int read_region_alpha(const char* filepath, char *region)
{
    FILE* file;
    int len;
    int res = 0;

    file = fopen(filepath, "r");
    if( file )
    {
        len = fread(region, 1, 2, file);
        if( len >= 0 )
        {
            if( len == 2 )
            {
                region[2] = 0;
                ALOGD("Read reg_alpha2 %s\n", region);
                res = 1;
            }
            else
            {
                ALOGE("read (%s) unexpected reg_alpha2 size %d", filepath, len);
            }
        }
        else
        {
            ALOGE("read (%s) failed: %s (%d)", filepath, strerror(errno), errno);
        }
        fclose(file);
        return res;
    }
    ALOGE("open (%s) failed: %s (%d)", filepath, strerror(errno), errno);
    return 0;
}

void format_mac_addr(void)
{
    unsigned short r = 0;
    unsigned short n = 0;

    strncpy(fmt_mac_addr, vendor_prefix, strlen(vendor_prefix));
    for(n = VENDOR_PREFIX_LENGTH * 3 /2; n < FMT_MAC_ADDR_LEN; n++ )
    {
        if( fmt_mac_addr[n] != ':' )
        {
            r = RANDOM(16);
            fmt_mac_addr[n] = hex_char[r];
        }
        else
        {
            n++;
        }
    }
}

int read_mac_from_file(char* mac_addr, const char *file_path)
{
    int ret = 0;
    FILE* fp = NULL;
    int sz;
    int len = 17;

    fp = fopen(file_path, "r");
    if (!fp)
    {
        ALOGE("open(%s) failed: %s (%d)", file_path, strerror(errno), errno);
        goto out;
    }

    sz = fread(mac_addr, 1, len, fp);
    mac_addr[len] = '\0';
    if (sz < 0)
    {
        ALOGE("read(%s) failed: %s (%d)", file_path, strerror(errno), errno);
        goto out;
    }
    else if (sz != len)
    {
        ALOGE("read(%s) unexpected MAC size %d", file_path, sz);
        goto out;
    }

    ret = 1;

    out:
    if (fp != NULL)
    {
        fclose(fp);
    }

    return ret;
}

int read_mac_from_cfg(char* mac_addr, const char *cfg_path)
{
    FILE* fp = NULL;
    char buf[1024];
    char* pos = NULL;

    fp = fopen(cfg_path, "r");
    if (!fp)
    {
        ALOGE("open(%s) failed: %s (%d)", cfg_path, strerror(errno), errno);
    }
	else
	{
		memset(buf, 0, sizeof(buf));
		fgets(buf, 1024, fp);
		pos = buf;
		if (strncmp(pos, "mac_addr", 8) == 0)
		{
			pos = strchr(pos, ':');
			if (pos != NULL)
			{
				strncpy(mac_addr, pos+2, FMT_MAC_ADDR_LEN);
			}
		}
	}
		
    if (fp != NULL)
    {
        fclose(fp);
    }
    return 0;
}

int check_psm_info()
{
    int fd;
    int res;
    char psm;

    fd = open(WIFI_DRIVER_MODULE_PSM_INFO, O_RDONLY);
    if( fd >= 0 )
    {
        if( read(fd, &psm, 1) >= 0 )
        {
            res = (psm == '0' ? 0 : 1);
        }
        else
        {
            res = 1;
            ALOGE("Read %s, Fail, %s", WIFI_DRIVER_MODULE_PSM_INFO, strerror(errno));
        }
    }
    else
    {
        res = 1;
        ALOGD("The wifi ps mode file doesn't exist");
    }
    return res;
}

void wifi_module_setup()
{
    static int need_wifi_mac_setup = 1;

    const char* hw_test;
    char region[20];
    if( need_wifi_mac_setup )
    {
        if( read_region_alpha(WIFI_DRIVER_MODULE_REGION_ALPHA_CONF, region) )
            write_param(WIFI_DRIVER_MODULE_REGION_ALPHA_CONF, region);

        if( access(WIFI_DRIVER_MODULE_MAC_INFO, 0) )
        {
            format_mac_addr();
            ALOGD("generate wifi mac address from random generator: %s\n", fmt_mac_addr);
        }
        else
        {
            read_mac_from_file(fmt_mac_addr, WIFI_DRIVER_MODULE_MAC_INFO);
            ALOGD("read wifi mac address from file %s: %s\n", WIFI_DRIVER_MODULE_MAC_INFO, fmt_mac_addr);
        }
        write_param(WIFI_DRIVER_MODULE_8777_MAC_ADDR_PARAM, fmt_mac_addr);
        need_wifi_mac_setup = 0;
    }
    write_param(WIFI_DRIVER_MODULE_8777_MFG_MODE_PARAM, "0");
    write_param(WIFI_DRIVER_MODULE_8777_CFG80211_WEXT_PARAM, "0xc");
    // Not in test mode
    if( check_psm_info() == 1 )
    {
        write_param(WIFI_DRIVER_MODULE_8777_AUTO_DS_PARAM, "0");
        write_param(WIFI_DRIVER_MODULE_8777_PS_MODE_PARAM, "0");
        hw_test = "0";
    }
    else
    {
        write_param(WIFI_DRIVER_MODULE_8777_AUTO_DS_PARAM, "2");
        write_param(WIFI_DRIVER_MODULE_8777_PS_MODE_PARAM, "2");
        hw_test = "1";
    }
    write_param(WIFI_DRIVER_MODULE_8777_HW_TEST_PARAM, hw_test);
}

void bluetooth_module_setup()
{
    static int need_bluetooth_mac_setup = 1;

    if( need_bluetooth_mac_setup )
    {
        if( access(BT_DRIVER_MODULE_BT_ADDR, 0) )
        {
            format_mac_addr();
            ALOGD("generate bt address from random generator: %s\n", fmt_mac_addr);
        }
        else
        {
            read_mac_from_file(fmt_mac_addr, BT_DRIVER_MODULE_BT_ADDR);
            ALOGD("read bt address from file %s: %s\n", BT_DRIVER_MODULE_BT_ADDR, fmt_mac_addr);
        }
        write_param(BT_DRIVER_MODULE_8777_BT_MAC_PARAM, fmt_mac_addr);
        need_bluetooth_mac_setup = 0;
    }
}

//Daemon entry
int main(void)
{
    int listenfd = -1;
    int clifd = -1;

    power_sd8xxx.on = FALSE;
    //register SIGINT and SIGTERM, set handler as kill_handler
    struct sigaction sa;
    sa.sa_flags = SA_NOCLDSTOP;
    sa.sa_handler = kill_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);
    /* Sometimes, if client close the socket unexpectedly, */
    /* we may continue to write that socket, then a SIGPIPE */
    /* would be delivered, which would cause the process exit; */
    /* but in fact, this SIGPIPE is harmless, so we should ignore it */
    signal(SIGPIPE,SIG_IGN);

    android_set_aid_and_cap();

    wifi_module_setup();
    bluetooth_module_setup();

    listenfd = serv_listen (WIRELESS_UNIX_SOCKET_DIR);
    if (listenfd < 0)
    {
        ALOGE("serv_listen error.\n");
        return -1;
    }
    ALOGI("succeed to create socket and listen.\n");
    while (!flag_exit)
    {
        clifd = serv_accept (listenfd);
        if (clifd < 0)
        {
            ALOGE("serv_accept error. \n");
            continue;
        }
        handle_thread(clifd);
        close (clifd);
    }
    close(listenfd);
    return 0;
}

void handle_thread(int clifd)
{
    int nread;
    char buffer[MAX_BUFFER_SIZE];
    char drive_card[MAX_BUFFER_SIZE]; // SoC modem
    int len = 0;
    int ret = 0;

    memset(drive_card, 0, MAX_BUFFER_SIZE);
    nread = read(clifd, buffer, sizeof (buffer));
    if (nread == SOCKERR_IO)
    {
        if (errno == EPIPE) {
            ALOGE("read error on fd [%d]: client close the socket\n", clifd);
        } else {
            ALOGE("read error on fd %d\n", clifd);
        }
    }
    else if (nread == SOCKERR_CLOSED)
    {
        ALOGE("fd %d has been closed.\n", clifd);
    }
    else
    {
        ALOGI("Got that! the data is %s\n", buffer);
        ret = cmd_handler(buffer, drive_card);
    }
    if(ret == 0)
    {
        strncpy(buffer, "0,OK ", sizeof(buffer));
        if( strnlen(drive_card, MAX_BUFFER_SIZE) <= 250 )
        {
            strncat(buffer, drive_card, MAX_BUFFER_SIZE-1);
        }
    }
    else
        strncpy(buffer, "1,FAIL", sizeof(buffer));

    nread = write(clifd, buffer, strlen(buffer));

    if (nread == SOCKERR_IO)
    {
        if (errno == EPIPE) {
            ALOGE("write error on fd [%d]: client close the socket\n", clifd);
        } else {
            ALOGE("write error on fd %d\n", clifd);
        }
    }
    else if (nread == SOCKERR_CLOSED)
    {
        ALOGE("fd %d has been closed.\n", clifd);
    }
}

//Command Handler
int cmd_handler(char* buffer, char* drive_card)
{
    int ret = 0;

    if(!strncmp(buffer, "WIFI_DISABLE", strlen("WIFI_DISABLE")))
        return wifi_disable();

    if (!strncmp(buffer, "WIFI_ENABLE", strlen("WIFI_ENABLE")))
        return wifi_enable();

    if (!strncmp(buffer, "BT_DISABLE", strlen("BT_DISABLE")))
        return bt_disable();

    if (!strncmp(buffer, "BT_ENABLE", strlen("BT_ENABLE")))
        return bt_enable();

    if (!strncmp(buffer, "FM_DISABLE", strlen("FM_DISABLE")))
        return fm_disable();

    if (!strncmp(buffer, "FM_ENABLE", strlen("FM_ENABLE")))
        return fm_enable();

    if(!strncmp(buffer, "NFC_DISABLE", strlen("NFC_DISABLE")))
        return nfc_disable();

    if(!strncmp(buffer, "NFC_ENABLE", strlen("NFC_ENABLE")))
        return nfc_enable();

    if (!strncmp(buffer, "BT_OFF", strlen("BT_OFF")))
    {
        power_sd8xxx.type.bt_on = 0;
        return set_power(0);
    }

    if (!strncmp(buffer, "BT_ON", strlen("BT_ON")))
    {
        power_sd8xxx.type.bt_on = 1;
        return set_power(1);
    }

    /* Note: The ' ' before the arg is needed */
    if (!strncmp(buffer, "WIFI_DRV_ARG ", strlen("WIFI_DRV_ARG ")))
        return set_drv_arg();

    /* Note: The ' ' before the arg is needed */
    if (!strncmp(buffer, "BT_DRV_ARG ", strlen("BT_DRV_ARG ")))
        return set_drv_arg();

	if (!strncmp(buffer, "MRVL_SD8XXX_FORCE_POWER_OFF", strlen("MRVL_SD8XXX_FORCE_POWER_OFF")))
        return mrvl_sd8xxx_force_poweroff();

    if (!strncmp(buffer, "WIFI_GET_FWSTATE", strlen("WIFI_GET_FWSTATE")))
        return wifi_get_fwstate();

    if (!strncmp(buffer, "GET_CARD_TYPE", strlen("GET_CARD_TYPE")))
        return get_card_type(drive_card);

    return 0;
}

#define    STALE    30    /* client's name can't be older than this (sec) */

/* returns new fd if all OK, < 0 on error */
int serv_accept (int listenfd)
{
    int                clifd, len;
    time_t             staletime;
    struct sockaddr_un unix_addr;
    struct stat        statbuf;
    const char*        pid_str;

    len = sizeof (unix_addr);
    if ( (clifd = accept (listenfd, (struct sockaddr *) &unix_addr, &len)) < 0)
    {
        ALOGE("listenfd %d, accept error: %s", listenfd, strerror(errno));
        return (-1);        /* often errno=EINTR, if signal caught */
    }
    return (clifd);
}

int serv_listen (const char* name)
{
    int fd,len;
    struct sockaddr_un unix_addr;

    /* Create a Unix domain stream socket */
    if ( (fd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
        return (-1);
    unlink (name);
    /* Fill in socket address structure */
    memset (&unix_addr, 0, sizeof (unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strcpy (unix_addr.sun_path, name);
    snprintf(unix_addr.sun_path, sizeof(unix_addr.sun_path), "%s", name);
    len = sizeof (unix_addr.sun_family) + strlen (unix_addr.sun_path);

    /* Bind the name to the descriptor */
    if (bind (fd, (struct sockaddr*)&unix_addr, len) < 0)
    {
        ALOGE("bind fd:%d and address:%s error: %s", fd, unix_addr.sun_path, strerror(errno));
        close (fd);
        return (-1);
    }
    if (chmod (name, 0666) < 0)
    {
        ALOGE("change %s mode error: %s", name, strerror(errno));
        close (fd);
        return (-1);
    }
    if (listen (fd, 5) < 0)
    {
        ALOGE("listen fd %d error: %s", fd, strerror(errno));
        close (fd);
        return (-1);
    }
    return (fd);
}

static void kill_handler(int sig)
{
    int result;
    int status;

    ALOGI("Received signal %d.", sig);

    if( sig == SIGCHLD )
    {
        while( 1 )
        {
            result = waitpid(-1, &status, WNOHANG);
            if( result <= 0 )
                break;
            ALOGI("child %d termination\n", 0);
        }
    }
    else
    {
        power_sd8xxx.on = FALSE;
        if( set_power(0) < 0 )
            ALOGE("set_power failed.");
        flag_exit = 1;
    }
}

int copy_wifi_bt_cfg(const char* filepath)
{
    if( !access(filepath, F_OK) )
        return 1;

    // Looks like Marvell forgot to install this script
    system("tcmd-subcase.sh copy-wifi-bt-cfg");
    return (access(filepath, F_OK) == 0);

}

void block_sigchld(int how)
{
    sigset_t sigset;

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGCHLD);
    if( sigprocmask(how, &sigset, 0) )
    {
        ALOGE("WARNING: blocksignal oper: %d signal:%d, %s (%d)", how, SIGCHLD, strerror(errno), errno);
    }
}

void check_wifi_bt_mac_addr()
{
    FILE *fp_bt = NULL;
    FILE *fp_wifi = NULL;
    char cfg_mac_addr[FMT_MAC_ADDR_LEN+1];
    char file_mac_addr[FMT_MAC_ADDR_LEN+1];

    if (access(wifi_mac_path, F_OK) == 0)
    {
        memset(cfg_mac_addr, 0, FMT_MAC_ADDR_LEN+1);
        memset(file_mac_addr, 0, FMT_MAC_ADDR_LEN+1);
        read_mac_from_file(file_mac_addr, wifi_mac_path);
        ALOGD("file wifi mac address: %s\n", file_mac_addr);
        read_mac_from_cfg(cfg_mac_addr, WIFI_DRIVER_MODULE_INIT_CFG_STORE_PATH);
        ALOGD("cfg wifi mac address: %s\n", cfg_mac_addr);
        if (memcmp(file_mac_addr, cfg_mac_addr, FMT_MAC_ADDR_LEN) != 0)
        {
            ALOGD("wifi mac address not consistent, update the wifi cfg file");
            fp_wifi = fopen(WIFI_DRIVER_MODULE_INIT_CFG_STORE_PATH, "w");
            if (fp_wifi)
            {
                fprintf(fp_wifi, "mac_addr = wlan0: %s\n", file_mac_addr);
                if(debug) ALOGD("update wifi mac_addr: %s\n", file_mac_addr);
                file_mac_addr[1] = '2';
                fprintf(fp_wifi, "mac_addr = p2p0: %s\n", file_mac_addr);
            }
            fclose(fp_wifi);
        }
    }

    if (access(bt_mac_path, F_OK) == 0)
    {
        memset(cfg_mac_addr, 0, FMT_MAC_ADDR_LEN+1);
        memset(file_mac_addr, 0, FMT_MAC_ADDR_LEN+1);
        read_mac_from_file(file_mac_addr, bt_mac_path);
        ALOGD("file bt mac address: %s\n", file_mac_addr);
        read_mac_from_cfg(cfg_mac_addr, BT_DRIVER_MODULE_INIT_CFG_STORE_PATH);
        ALOGD("cfg bt mac address: %s\n", cfg_mac_addr);
        if (memcmp(file_mac_addr, cfg_mac_addr, FMT_MAC_ADDR_LEN) != 0)
        {
            ALOGD("bt mac address not consistent, update the bt cfg file");
            fp_bt = fopen(BT_DRIVER_MODULE_INIT_CFG_STORE_PATH, "w");
            if (fp_bt)
            {
                fprintf(fp_bt, "mac_addr = mbtchar0: %s\n", file_mac_addr);
                if(debug) ALOGD("update bt mac_addr: %s\n", file_mac_addr);
            }
            fclose(fp_bt);
        }
    }
}

void MSRAND(void)
{
	struct timeval tv;
	unsigned int seed;
	gettimeofday(&tv, NULL);
	seed = tv.tv_sec * 1000000 + tv.tv_usec;
	srand(seed);
}

int create_wifi_bt_init_cfg()
{
    unsigned short i = 0;
    FILE *fp_bt = NULL;
    FILE *fp_wifi = NULL;
    int ret = -1;
    int size = 0;

    fp_bt = fopen(BT_DRIVER_MODULE_INIT_CFG_STORE_PATH, "w" );
    if( !fp_bt )
    {
        ALOGE("create the file %s failed, error:%s\n", BT_DRIVER_MODULE_INIT_CFG_STORE_PATH, strerror(errno));
        goto err;
    }
    fp_wifi = fopen(WIFI_DRIVER_MODULE_INIT_CFG_STORE_PATH, "w" );

    if( !fp_wifi )
    {
        ALOGE("create the file %s failed, error:%s\n", WIFI_DRIVER_MODULE_INIT_CFG_STORE_PATH, strerror(errno));
        goto err;
    }

    MSRAND();

    if (access(bt_mac_path, F_OK) == 0)
    {
        read_mac_from_file(fmt_mac_addr, bt_mac_path);
        ALOGD("read bt mac address from file %s: %s\n", bt_mac_path, fmt_mac_addr);
    }
    else
    {
        format_mac_addr();
        ALOGD("generate bt mac address from random generator: %s\n", fmt_mac_addr);
    }
    size = fprintf( fp_bt, "mac_addr = mbtchar0: %s\n",fmt_mac_addr);
    if(debug) ALOGD("mac_addr = mbtchar0: %s\n",fmt_mac_addr);
    if(size <= 0)
    {
        ALOGE("write the file %s failed, error:%s\n", BT_DRIVER_MODULE_INIT_CFG_STORE_PATH, strerror(errno));
        goto err;
    }

    if (access(wifi_mac_path, F_OK) == 0)
    {
        read_mac_from_file(fmt_mac_addr, wifi_mac_path);
        ALOGD("read wifi mac address from file %s: %s\n", wifi_mac_path, fmt_mac_addr);
    }
    else
    {
        format_mac_addr();
        ALOGD("generate wifi mac address from random generator: %s\n", fmt_mac_addr);
    }
    size = fprintf( fp_wifi, "mac_addr = wlan0: %s\n",fmt_mac_addr);
    if(debug) ALOGD("mac_addr = wlan0: %s\n",fmt_mac_addr);
    if(size <= 0)
    {
        ALOGE("write the file %s failed, error:%s\n", WIFI_DRIVER_MODULE_INIT_CFG_STORE_PATH, strerror(errno));
        goto err;
    }

    fmt_mac_addr[1] = '2';
    size  = fprintf( fp_wifi, "mac_addr = p2p0: %s\n",fmt_mac_addr);
    if(debug) ALOGD("mac_addr = p2p0: %s\n",fmt_mac_addr);
    if(size <= 0)
    {
        ALOGE("write the file %s failed, error:%s\n", WIFI_DRIVER_MODULE_INIT_CFG_STORE_PATH, strerror(errno));
        goto err;
    }

    ret = 0;
err:
    if(fp_bt != NULL)fclose(fp_bt);
    if(fp_wifi != NULL)fclose(fp_wifi);
    if(ret != 0)
    {
        unlink(BT_DRIVER_MODULE_INIT_CFG_STORE_PATH);
        unlink(WIFI_DRIVER_MODULE_INIT_CFG_STORE_PATH);
    }
    return ret;
}

int kill_process_by_name(const char* ProcName)
{
    DIR             *dir = NULL;
    struct dirent   *d = NULL;
    int             pid = 0;
    char comm[PATH_MAX+1];
    /* Open the /proc directory. */
    dir = opendir("/proc");
    if (!dir)
    {
        printf("cannot open /proc");
        return -1;
    }
    /* Walk through the directory. */
    while ((d = readdir(dir)) != NULL)
	{
        /* See if this is a process */
        if ((pid = atoi(d->d_name)) == 0) continue;
        snprintf(comm, sizeof(comm), "/proc/%s/comm", d->d_name);
        FILE *fp = fopen(comm, "r");
        if (fp)
		{
            char line[1024];
            char *pos = NULL;
            while (fgets(line, sizeof(line), fp))
			{
                line[strlen(line)-1] = '\0';
                if (strncmp(line, ProcName, strlen(ProcName)) == 0)
				{
                    ALOGI("Try to kill pid[%d][%s]\n", pid, ProcName);
                    if (kill(pid, SIGKILL) != 0)
					{
                        ALOGE("Fail to kill pid[%d][%s], error[%s]\n", pid, ProcName, strerror(errno));
                    }
                }
            }
            fclose(fp);
        }
    }
    closedir(dir);
    return  0;
}

//to do: don’t use polling mode, use uevent, listen interface added uevent from driver
int wait_interface_ready (int interface, int us_interval, int retry)
{
    const char* interface_path;
    int fd;
    int count = retry;
    struct stat fstat;
    int i;
    char permissions[10];

    switch( interface )
    {
        case WIFI_DRIVER_IFAC_INDEX: interface_path = WIFI_DRIVER_IFAC_NAME; break;
        case BT_DRIVER_DEV_INDEX   : interface_path = BT_DRIVER_DEV_NAME; break;
        case FM_DRIVER_DEV_INDEX   : interface_path = FM_DRIVER_DEV_NAME; break;
        case NFC_DRIVER_DEV_INDEX  : interface_path = NFC_DRIVER_DEV_NAME; break;
        default:
            ALOGE("Unknown module!");
            return -1;
    }
    while( count-- )
    {
        fd = open(interface_path, O_RDONLY);
        if( fd >= 0 )
        {
            close(fd);
            if( stat(interface_path, &fstat) == 0 )
            {
                for( i = 0; i < 9; ++i )
                {
                    if( right_masks[i] & fstat.st_mode )
                        permissions[i] = rights[i];
                    else
                        permissions[i] = '-';
                }
                permissions[9] = 0;
                ALOGE("File name: %s", interface_path);
                ALOGE("Permissions: %s", permissions);
                ALOGE("User-id: %ld,Group-id: %ld", (long int)fstat.st_uid, (long int)fstat.st_gid);
                //                                                                                                                       net_bt_stack
                if( interface != BT_DRIVER_DEV_INDEX || fstat.st_uid == AID_BLUETOOTH || fstat.st_gid == AID_BLUETOOTH || fstat.st_gid == 3008 )
                    return 0;
            }

        }
        usleep(us_interval);
    }

    ALOGE("timeout(%dms) to wait %s", us_interval * retry / 1000, interface_path);
    return -1;
}

int set_drv_arg()
{
	ALOGE("Driver is built into kernel, fail to set the arg!");
	return -1;
}

int set_power(int on)
{
    int res = 0;

    ALOGI("%s: on=%d", __func__, on);
    if( on )
    {
        res = system("echo 1 > " WIRELESS_POWER_SET_PATH);
        if( res )
        {
            ALOGE("---------echo 1 > " WIRELESS_POWER_SET_PATH ", ret: 0x%x, strerror: %s", res, strerror(errno));
        }
    }
    else if( !power_sd8xxx.on )
    {
        res = system("echo 0 > " WIRELESS_POWER_SET_PATH);
        if( res )
        {
            ALOGE("---------echo 0 > " WIRELESS_POWER_SET_PATH ", ret: 0x%x, strerror: %s", res, strerror(errno));
        }
    }

    return res;
}

int mrvl_sd8xxx_force_poweroff()
{
	int ret = 0;
	int v2; // r4
	int *v3; // r0
	char *v4; // r0
	char buffer[92]; // [sp+8h] [bp-78h]

	memset(buffer, 0, sizeof(buffer));
	property_get("persist.sys.mrvl_wl_recovery", buffer, "1");
	if ( atoi(buffer) )
	{
		ALOGE("mrvl_sd8xxx_force_poweroff");
		ret = system("echo 0 > /sys/devices/platform/sd8x-rfkill/pwr_ctrl");
		if ( ret )
		{
			ALOGE("---------echo 0 > /sys/devices/platform/sd8x-rfkill/pwr_ctrl, ret: 0x%x, strerror: %s", ret, strerror(errno));
		}
		else
		{
			if ( power_sd8xxx.type.bt_on )
			{
				ALOGE("mrvl_sd8xxx_force_poweroff: kill BT");
				kill_process_by_name("droid.bluetooth");
			}
			if ( power_sd8xxx.type.fm_on )
			{
				ALOGE("mrvl_sd8xxx_force_poweroff: kill FM");
				kill_process_by_name("FMRadioServer");
			}
			if ( power_sd8xxx.type.nfc_on )
			{
				ALOGE("mrvl_sd8xxx_force_poweroff: kill NFC");
				kill_process_by_name("com.android.nfc");
			}
		}
	}
	else
	{
		ALOGE("The recovery feature has been disabled, ignore the command: force power off!To enable it, please set the property: persist.sys.mrvl_wl_recovery");
		ret = -1;
	}
	return ret;
}

int bt_fm_disable(void)
{
    int res = 0;
    /* To speed up the recovery, detect the FW status here */
    if (wifi_get_fwstate() == FW_STATE_HUNG || (res = mrvl_sd8xxx_force_poweroff()) != 0 )
    {
        res = set_power(0);
    }
    return res;
}

int bt_fm_enable(void)
{
    int ret = 0;
    char arg_buf[MAX_BUFFER_SIZE];

    ALOGD("%s(L%d): ", __func__, 1002);
    ALOGD(__func__);

    memset(arg_buf, 0, MAX_BUFFER_SIZE);

    if( copy_wifi_bt_cfg(BT_DRIVER_MODULE_INIT_CFG_STORE_PATH) )
    {
        ALOGD("The bluetooth config file exists");
        check_wifi_bt_mac_addr();
    }
    else
    {
        ALOGD("The bluetooth config file doesn't exist");
        if( create_wifi_bt_init_cfg() )
            ALOGD("create wifi bt init cfg file failed");
    }
    if( access(BT_DRIVER_MODULE_INIT_CFG_STORE_PATH, F_OK) )
        ALOGD("Couldn't access %s!", BT_DRIVER_MODULE_INIT_CFG_STORE_PATH);

    bluetooth_module_setup();
    ret = set_power(1);
    if( ret < 0 )
    {
        ALOGD("%s, set_power fail: errno: %d, %s", __func__, errno, strerror(errno));
    }
    return ret;
}

int wifi_uap_enable()
{
    int res;

    ALOGD("wifi_uap_enable_builtin");
    if( copy_wifi_bt_cfg(WIFI_DRIVER_MODULE_INIT_CFG_STORE_PATH) )
    {
        ALOGD("The wifi config file exists");
        check_wifi_bt_mac_addr();
    }
    else
    {
        ALOGD("The wifi config file doesn't exist");
        if( create_wifi_bt_init_cfg() )
            ALOGD("create wifi bt init cfg file failed");
    }

    if( access(WIFI_DRIVER_MODULE_INIT_CFG_STORE_PATH, F_OK) )
        ALOGD("Couldn't access %s!", WIFI_DRIVER_MODULE_INIT_CFG_STORE_PATH);
    // Marvell is wrong here ? They put /system/etc/firmware/mrvl/mrvl/wifi_cal_data.conf
    // But this file exists in /system/etc/firmware/mrvl/wifi_cal_data.conf
    if( !copy_wifi_bt_cfg(WIFI_DRIVER_MODULE_CAL_DATA_CFG_STORE_PATH) )
        ALOGD("The wifi calibrate file does not exist");

    wifi_module_setup();
    res = set_power(1);
    if( res < 0)
        ALOGD("%s, set_power fail", __func__);

    return res;
}

int wifi_enable(void)
{
    int ret = 0;

    power_sd8xxx.type.wifi_on = TRUE;
    block_sigchld(SIG_BLOCK);
    ret = wifi_uap_enable();

    if( ret < 0 )
    {
        power_sd8xxx.type.wifi_on = FALSE;
        property_set(DRIVER_PROP_NAME, "failed");
    }
    else
    {
        ret = wait_interface_ready(0, 1000, 8000);
        if(ret < 0)
        {
            power_sd8xxx.type.wifi_on = FALSE;
            property_set(DRIVER_PROP_NAME, "timeout");
        }
        else
        {
            property_set(DRIVER_PROP_NAME, "ok");
        }
    }
    block_sigchld(SIG_UNBLOCK);

    return ret;
}

int wifi_disable(void)
{
    int ret = 0;

    power_sd8xxx.type.wifi_on = FALSE;

    block_sigchld(SIG_BLOCK);
    ret = bt_fm_disable();
    block_sigchld(SIG_UNBLOCK);

    if(ret == 0)
    {
        property_set(DRIVER_PROP_NAME, "unloaded");
    }
    else
    {
        property_set(DRIVER_PROP_NAME, "failed");
    }
    return ret;
}

int bt_enable(void)
{
    int ret = 0;

    power_sd8xxx.type.bt_on = TRUE;
    block_sigchld(SIG_BLOCK);

    ret = bt_fm_enable();

    if (ret < 0) {
        ALOGE("Fail to enable bt!");
        goto out;
    }
    ret = wait_interface_ready(BT_DRIVER_DEV_INDEX, 200000, 40);
    if(ret < 0)
    {
        ALOGE("Timeout to wait /dev/mbtchar0!");
        goto out;
    }
    get_driver_version(1);
out:
    block_sigchld(SIG_UNBLOCK);
    if( ret < 0 )
        power_sd8xxx.type.bt_on = FALSE;

    return ret;
}

int bt_disable()
{
    int ret;

    power_sd8xxx.type.bt_on = FALSE;
    block_sigchld(SIG_BLOCK);
    ret = bt_fm_disable();
    block_sigchld(SIG_UNBLOCK);

    return ret;
}

int fm_enable(void)
{
    int ret = 0;
    power_sd8xxx.type.fm_on = TRUE;

    ret = bt_fm_enable();
    if(ret >= 0)
	{
		ret = wait_interface_ready(FM_DRIVER_DEV_INDEX, 200000, 40);
		if(ret >= 0)
		{
			get_driver_version(2);
			return ret;
		}
		ALOGE("Timeout to wait /dev/mfmchar0!");
	}
	else
	{
        ALOGE("Fail to enable bt_fm!");
	}
	
	power_sd8xxx.type.fm_on = FALSE;
	
    return ret;
}

int fm_disable()
{
    power_sd8xxx.type.fm_on = FALSE;
    return bt_fm_disable();
}

int nfc_enable()
{
	int ret;

	power_sd8xxx.type.nfc_on = TRUE;

	ret = bt_fm_enable();
	if ( ret < 0 )
	{
		ALOGE("Fail to enable nfc!");
		power_sd8xxx.type.nfc_on = FALSE;
	}
	else
	{
		ret = wait_interface_ready(NFC_DRIVER_DEV_INDEX, 200000, 40);
		if ( ret < 0 )
		{
			ALOGE("Timeout to wait /dev/mnfcchar0!");
			power_sd8xxx.type.nfc_on = FALSE;
		}
	}
  return ret;
}

int nfc_disable()
{
	power_sd8xxx.type.nfc_on = FALSE;
	return bt_fm_disable();
}

int get_wifi_state()
{
	FILE *file;
	int ret;
	char *substr;
	char buffer[1024];

	file = fopen("/proc/mwlan/wlan0/debug", "r");
	if ( file == NULL )
		return 0;
	
	while ( 1 )
	{
		substr = fgets(buffer, 1024, file);
		if ( substr == NULL )
		{
			ret = 0;
			break;
		}
		buffer[strnlen(buffer, 1024) - 1] = 0;
		if ( !strncmp(buffer, "driver_state=", 13) )
		{
			ret = atoi(&buffer[13]);
			break;
		}
	}
	fclose(file);
	
	return ret;
}

int wifi_get_fwstate()
{
	int param;
	char param_str[92];
	
	memset(param_str, 0, sizeof(param));
	property_get(MRVL_PROP_WL_RECOVERY, param_str, "1");
	param = atoi(param_str);
	if( param )
	{
		return get_wifi_state();
	}
	ALOGE("The recovery feature has been disabled, ignore the command: wifi get fwstate!To enable it, please set the property:\n" MRVL_PROP_WL_RECOVERY);
	return 0;
}

const char* read_driver_info(FILE *file, char *buffer, int type, int is_status_file)
{
	char *key;
	const char* ret = NULL;
	
	// If its a 'status' file, then get the driver version
	if( !is_status_file )
	{
		if( type == WIFI_DRIVER_IFAC_INDEX )
			key = "driver_version";
		else
			key = "version";
	}
	// else get the debug info ?
	else
		key = "drvdbg";
	
	if( file )
	{
		if( buffer )
		{
			while( (ret = fgets(buffer, 1024, file)) )
			{
				if( (ret = strstr(buffer, key)) )
				{
					ALOGI("%s", ret);
					break;
				}
				memset(buffer, 0, 4);
			}
			if( ret == NULL )
				ALOGI("No driver info found");
		}
	}
	
	return ret;
}

void get_driver_version(int type)
{
	struct driver_debug_t *driver_debug_paths;
	const char* driver_info_line;
	char cmd[256];
	char info[256];
	char buffer[1024];
	
	FILE *file;
	
	memset(cmd, 0, sizeof(cmd));
	memset(info, 0, sizeof(info));
	memset(buffer, 0, sizeof(buffer));
	if( type < TYPE_SD8xxx )
	{
		driver_debug_paths = &drivers_debug[type];
		if( strlen(driver_debug_paths->status) < 252 && strlen(driver_debug_paths->config) < 252 )
		{
			// Prepare to read status file
			strncat(cmd, "cat ", 255);
			strncat(cmd, driver_debug_paths->status, 255);
			file = popen(cmd, "r");
			if( file )
			{
				driver_info_line = read_driver_info(file, buffer, type, 0);
				strncat(info, driver_info_line, 255);
				fclose(file);
				property_set(android_persist_prop[type], info);
				
				// Prepare to read config file
				memset(buffer, 0, sizeof(buffer));
				memset(cmd, 0, sizeof(cmd));
				strncat(cmd, "cat ", 255);
				strncat(cmd, driver_debug_paths->config, 255);
				file = popen(cmd, "r");
				if( file )
				{
					driver_info_line = read_driver_info(file, buffer, type, 1);
					strncat(info, driver_info_line, 255);
					fclose(file);
				}
				else
				{
					ALOGE("%s config failed: %s (%d)", __func__, strerror(errno), errno);
				}
			}
			else
			{
				ALOGE("%s status failed: %s (%d)", __func__, strerror(errno), errno);
			}
		}
		else
		{
			ALOGE("Exceeded command buffer length, abort");
		}
	}
	else
	{
		ALOGE("Invalid driver name index: %d", type);
	}
}

int hex_to_int(const char *str)
{
	int ret = 0;
	unsigned char c;
	
	if( str )
	{
		str+=2;
		while( *str )
		{
			c = (unsigned char)*str;
			// 'a' = 97
			if( (c - 'a') <= 5 )
			{
				// 'W' = 87
				c -= 87;
			}
			// 'A' = 65
			else if( (c - 'A') <= 5 )
			{
				// '7' = 55
				c -= 55;
			}
			// '0' = 48
			else if( (c - '0') > 9 )
			{
				if( c != '\n' && c != '\r' )
				{
					ALOGE("Illegal hex number");
					return -1;
				}
			}
			else
			{
				// '0' = 48
				c -= '0';
			}
			ret = c + 16 * ret;
		}
		return ret;
	}
	return -1;
}

int get_sdio_card_type(int x)
{
	char buffer[1024];
	FILE* file;
	int sdio_card_id;
	
	if( x == 1 )
		return TYPE_SD8xxx;
	
	memset(buffer, 0, sizeof(buffer));
	file = popen("cat " SDIO_DEVICE_PATH, "r");
	if( !file )
	{
		ALOGE("%s failed: %s (%d)", __func__, strerror(errno), errno);
		return -1;
	}
	if( !fgets(buffer, 1024, file) )
	{
		ALOGI("nothing is read from %s", SDIO_DEVICE_PATH);
		fclose(file);
		return -1;
	}
	if( !strncmp("0x", buffer, 2) )
		sdio_card_id = hex_to_int(buffer);
	else
		sdio_card_id = atoi(buffer);
	
	fclose(file);
	ALOGI("sdio card id %lx", (long unsigned int)sdio_card_id);
	
	switch( sdio_card_id )
	{
		case CARD_ID_SD8777: return sdio_types[0].index;
		case CARD_ID_SD8787: return sdio_types[1].index;
		case CARD_ID_SD8887: return sdio_types[2].index;
		case CARD_ID_SD8897: return sdio_types[3].index;
		default            : return sdio_types[4].index;
	}
}

int get_card_type(char *card_type)
{
	int type;
	if( !power_sd8xxx.on )
	{
		ALOGE("failed to get card type: SDIO card is not powered up");
		return -1;
	}
	type = get_sdio_card_type(0);
	if( type >= TYPE_SD8xxx )
	{
		ALOGE("Unknown card type: %lu", (long unsigned int)type);
		return -1;
	}
	sprintf(card_type, "%lu %s", (long unsigned int)type, sdio_types[type].name);
	return 0;
}
