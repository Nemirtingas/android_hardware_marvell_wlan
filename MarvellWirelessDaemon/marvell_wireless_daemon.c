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

static const char* WIFI_DRIVER_IFAC_NAME =         "/sys/class/net/wlan0";

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
static const char* WIRELESS_POWER_SET_PATH = "/sys/devices/platform/sd8x-rfkill/pwr_ctrl";

static const char DRIVER_PROP_NAME[]    = "wlan.driver.status";

static const char* RFKILL_SD8X_PATH = "/sys/class/rfkill/rfkill0/state";

static const char* BT_DRIVER_DEV_NAME = "/dev/mbtchar0";
static const char* FM_DRIVER_DEV_NAME = "/dev/mfmchar0";

static const char* MRVL_PROP_WL_RECOVERY = "persist.sys.mrvl_wl_recovery";

static int flag_exit = 0;
static int debug = 1;

static const char* base_mac = "00:50:43:00:00:00";
static char mac_addr[20];
static int exit_main = 0;

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
        while( 1 )
        {
            fd = open(filepath, 1);
            if( fd != -1 )
                break;

            if( errno != EINTR )
            {
                ALOGE("Failed to open: %s (%s) %d", filepath, strerror(errno), errno);
                return -1;
            }
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
            ALOGE("Failed to write param: %s (%s) %d", param, strerro(errno), errno);
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

    file = fopen(filepath);
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

void setup_random_mac_addr()
{
    int i;
    int res;
    const char numalpha[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

    strncpy(mac_addr, base_mac, strlen(base_mac));
    for( i = 9; i < 17; ++i )
    {
        if( mac_addr[i] == ':' )
        {
            ++i
        }
        else
        {
            mac_addr[i] = numalpha[rand() % 16];
        }
    }
}

void setup_file_mac_addr(char *addr, const char *filepath)
{
    FILE* file;
    int read;

    file = fopen(filepath, "r");
    if( file )
    {
        read = fread(addr, 1, 17, file);
        addr[17] = 0;
        if( read >= 0 )
        {
            if( read != 17 )
                ALOGE("read(%s) unexpected MAC size %d", filepath, strerror(errno), errno);
        }
        else
        {
            ALOGE("read(%s) failed: %s (%d)", filepath, strerror(errno), errno);
        }
        fclose(file);
    }
    else
    {
        ALOGE("open(%s) failed: %s (%d)", filepath, strerror(errno), errno);
    }
}

int check_psm_info()
{
    int fd;
    int res;
    char psm;

    fd = open(WIFI_DRIVER_MODULE_PSM_INFO, 0);
    if( fd >= 0 )
    {
        if( read(fd, &psm, 1) >= 0 )
        {
            res = (psm == '0' ? 0 : 1);
        }
        else
        {
            res = 1;
            ALOGE("Read %s, Fail, %s", WIFI_DRIVER_MODULE_PSM_INFO);
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
            setup_random_mac_addr();
            ALOGD("generate wifi mac address from random generator: %s\n", mac_addr);
        }
        else
        {
            setup_file_mac_addr(mac_addr, WIFI_DRIVER_MODULE_MAC_INFO);
            ALOGD("read wifi mac address from file %s: %s\n", WIFI_DRIVER_MODULE_MAC_INFO, mac_addr);
        }
        write_param(WIFI_DRIVER_MODULE_8777_MAC_ADDR_PARAM, mac_addr);
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
            setup_random_mac_addr();
            ALOGD("generate bt address from random generator: %s\n", mac_addr);
        }
        else
        {
            setup_file_mac_addr(mac_addr, BT_DRIVER_MODULE_BT_ADDR);
            ALOGD("read bt address from file %s: %s\n", BT_DRIVER_MODULE_BT_ADDR, mac_addr);
        }
        write_param(BT_DRIVER_MODULE_8777_BT_MAC_PARAM, mac_addr);
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
    while (!exit_main)
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
            strncat(buffer, drive_card, MAX_BUFFER_SIZE);
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

    if (!strncmp(buffer, "WIFI_DRV_ARG ", strlen("WIFI_DRV_ARG ")))
    {
        /* Note: The ' ' before the arg is needed */
        return set_drv_arg();
    }

    if (!strncmp(buffer, "BT_DRV_ARG ", strlen("BT_DRV_ARG")))
    {
        /* Note: The ' ' before the arg is needed */
        return set_drv_arg();
	}

	if (!strncmp(buffer, "MRVL_SD8XXX_FORCE_POWER_OFF", strlen("MRVL_SD8XXX_FORCE_POWER_OFF")))
	{
        return mrvl_sd8xxx_force_poweroff();
    }

    if (!strncmp(buffer, "WIFI_GET_FWSTATE", strlen("WIFI_GET_FWSTATE")))
    {
        return wifi_get_fwstate();
    }

    if (!strncmp(buffer, "GET_CARD_TYPE", strlen("GET_CARD_TYPE")))
	{
        return get_card_type(drive_card);
    }
}

void modem_disable()
{
    if( wifi_get_fwstate() != 1 || mrvl_sd8xxx_force_poweroff() )
        set_power(0);
}

int copy_wifi_bt_cfg(const char* filepath)
{
    if( !access(filepath, 0) )
        return 1;

    // Looks like Marvell forgot to install this script
    system("tcmd-subcase.sh copy-wifi-bt-cfg");
    return (access(filepath, 0) == 0);

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

int wifi_uap_enable()
{

    ALOGD("wifi_uap_enable_builtin");
    if( copy_wifi_bt_cfg(WIFI_DRIVER_MODULE_INIT_CFG_STORE_PATH) )
}

int wifi_enable(void)
{
    int ret = 0;

    power_sd8xxx.type.wifi_on = TRUE;
    block_sigchld(SIG_BLOCK);
    ret = wifi_uap_enable();

    if(ret < 0)goto out;
    ret = wait_interface_ready(WIFI_DRIVER_IFAC_NAME, 1000, 2000);
    if(ret < 0)
    {
        property_set(DRIVER_PROP_NAME, "timeout");
        goto out;
    }
#ifdef SD8887_NEED_CALIBRATE
    ret = wifi_calibrate();
#endif
out:
    if(ret == 0)
    {
        property_set(DRIVER_PROP_NAME, "ok");
    }
    else
    {
        property_set(DRIVER_PROP_NAME, "failed");
    }
    return ret;
}

int wifi_disable(void)
{
    int ret = 0;

    power_sd8xxx.type.wifi_on = FALSE;

    block_sigchld(SIG_BLOCK);
    ret = modem_disable();
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
