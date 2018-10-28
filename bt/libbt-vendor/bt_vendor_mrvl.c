/*
 * Copyright 2012 The Android Open Source Project
 * Copyright (c) 2013, The Linux Foundation. All rights reserved.
 * Not a Contribution.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/******************************************************************************
 *
 *  Filename:      bt_vendor_mrvl.c
 *
 *  Description:   vendor specific library implementation
 *
 ******************************************************************************/

#define LOG_TAG "bluedroid-mrvl"
//#define BLUETOOTH_MAC_ADDR_BOOT_PROPERTY "ro.boot.btmacaddr"

#include <utils/Log.h>
#include <cutils/properties.h>
#include <fcntl.h>
#include "bt_vendor_mrvl.h"
#include "marvell_wireless.h"

#define WAIT_TIMEOUT 200000

/******************************************************************************
**  Variables
******************************************************************************/
bt_vendor_callbacks_t *bt_vendor_cbacks = NULL;
uint8_t vnd_local_bd_addr[6]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
int bt_sock = -1;

static const char BT_DEV_PATH[] = "/dev/mbtchar0";
static const char BT_PCMMASTER_PROP[] = "persist.bt.pcmmaster";

/******************************************************************************
**  Local type definitions
******************************************************************************/


/******************************************************************************
**  Functions
******************************************************************************/
int btsnd_hcic_set_pcm_voice_path()
{
    char *buf;
    
    buf = bt_vendor_cbacks->alloc(12);
    if( buf == NULL )
        return 1;

    *(short*)&buf[0] = 8192;
    *(short*)&buf[2] = 6;
    *(short*)&buf[4] = 0;
    *(short*)&buf[6] = 0;
    buf[8]  = 29;
    buf[9]  = -4;
    buf[10] = 1;
    buf[11] = 1;
    if( !bt_vendor_cbacks->xmit_cb(0xFC1D, buf, 0) )
    {
        bt_vendor_cbacks->dealloc(buf);
        return 1;
    }
    return 0;
}

int btsnd_hcic_set_pcm_sync()
{
    char pcmmaster[PROP_VALUE_MAX];   
    int state;
    char *buf;

    property_get(BT_PCMMASTER_PROP, pcmmaster, "1");
    if( strcmp(pcmmaster, "0") == 0 )
        state = 0;
    else
        state = 3;

    buf = bt_vendor_cbacks->alloc(14);
    if( buf == NULL )
        return 1;

    *(short*)&buf[0] = 8192;
    *(short*)&buf[2] = 6;
    *(short*)&buf[4] = 0;
    *(short*)&buf[6] = 0;
    buf[8]  = 40;
    buf[9]  = -4;
    buf[10] = 3;
    buf[11] = 3;
    buf[12] = 0;
    buf[13] = state;
    if( !bt_vendor_cbacks->xmit_cb(0xFC28, buf, NULL) )
    {
        bt_vendor_cbacks->dealloc(buf);
        return 1;
    }
    return 0;
}

int btsnd_hcic_set_pcm_mode()
{
    char pcmmaster[PROP_VALUE_MAX];
    int state;
    char *buf;
    property_get(BT_PCMMASTER_PROP, pcmmaster, "1");
    if( strcmp(pcmmaster, "0") == 0 )
        state = 0;
    else
        state = 2;

    buf = bt_vendor_cbacks->alloc(12);
    if( buf == NULL )
        return 1;

    *(short*)&buf[0] = 8192;
    *(short*)&buf[2] = 4;
    *(short*)&buf[4] = 0;
    *(short*)&buf[6] = 0;
    buf[8]  = 7;
    buf[9]  = -4;
    buf[10] = 1;
    buf[11] = state;
    if( !bt_vendor_cbacks->xmit_cb(0xFC07, buf, NULL) )
    {
        bt_vendor_cbacks->dealloc(buf);
        return 1;
    }
    return 0;
}

int btsnd_hcic_set_pcm_link()
{
    char *buf;

    buf = bt_vendor_cbacks->alloc(13);
    if( buf == NULL )
        return 1;

    *(short*)&buf[0] = 8192;
    *(short*)&buf[2] = 5;
    *(short*)&buf[4] = 0;
    *(short*)&buf[6] = 0;
    buf[8]  = 41;
    buf[9]  = -4;
    buf[10] = 2;
    buf[11] = 4;
    buf[12] = 0;
    if( !bt_vendor_cbacks->xmit_cb(0xFC29, buf, NULL) )
    {
        bt_vendor_cbacks->dealloc(buf);
        return 1;
    }
    return 0;
}

void bt_set_sco_codec_cback(void *param)
{
    char *buf = (char*)param;
    if( buf[13] )
    {
        ALOGE("%s: Setting Codec Failed %d", __func__, buf[13]);
    }
    else
    {
        ALOGI("%s: OpCode 0x%04x Status %d", __func__, (short)(buf[11] + ((short)buf[12]<<8)), buf[13]);
        bt_vendor_cbacks->dealloc(buf);
    }
}

int bt_set_sco_codec_cmd(void *param)
{
    int *iparam = (int*)param;
    int codec = iparam[1];
    char *buf;
    int ret = 0;

    ALOGI("%s: Handle %d, codec %d, state %d", __func__, iparam[0], codec, iparam[2]);
    if( bt_vendor_cbacks != NULL )
    {
        buf = bt_vendor_cbacks->alloc(12);
        if( buf )
        {
            *(short*)&buf[0] = 8192;
            *(short*)&buf[2] = 4;
            *(short*)&buf[4] = 0;
            *(short*)&buf[6] = 0;
            buf[8]  = 115;
            buf[9]  = -4;
            buf[10] = 1;
            buf[11] = (codec - 2) <= 0;
            ret = bt_vendor_cbacks->xmit_cb(0xFC73, buf, bt_set_sco_codec_cback);
            if( ret )
                return ret;
            bt_vendor_cbacks->dealloc(buf);
        }
        ALOGI("%s: vendor lib postload aborted", __func__);
        bt_vendor_cbacks->scocfg_cb(BT_VND_OP_RESULT_SUCCESS);
    }
    return ret;
}

/*****************************************************************************
**
**   BLUETOOTH VENDOR INTERFACE LIBRARY FUNCTIONS
**
*****************************************************************************/

static int bt_vnd_mrvl_if_init(const bt_vendor_callbacks_t* p_cb, unsigned char *local_bdaddr)
{
    int i;

    ALOGI("%s called", __func__);

    bt_vendor_cbacks = (bt_vendor_callbacks_t*)p_cb;
    if(local_bdaddr)
        for(i=0;i<6;i++)
            vnd_local_bd_addr[i] = local_bdaddr[i];

    ALOGI("%s: Local BD Address : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x", __func__,
                                                vnd_local_bd_addr[0],
                                                vnd_local_bd_addr[1],
                                                vnd_local_bd_addr[2],
                                                vnd_local_bd_addr[3],
                                                vnd_local_bd_addr[4],
                                                vnd_local_bd_addr[5]);
    return 0;
}

/** Requested operations */
static int bt_vnd_mrvl_if_op(bt_vendor_opcode_t opcode, void *param)
{
    ALOGI("%s: opcode = %d", __func__, opcode);

    int *iparam = (int*)param;
    int ret = 0;
    int retry = 1;

    switch( opcode )
    {
        case BT_VND_OP_POWER_CTRL   : 
            if( *iparam == BT_VND_PWR_ON )
            {
                ALOGI("%s: power on", __func__);
                do
                {
                    ret = bluetooth_enable();
                    ALOGI("%s: bluetooth_enable, ret: 0x%x", __func__, ret);
                    if( ret == 0 ) return 0;
                    ALOGI("%s: Fail to enable BT the [%d] time force power off", __func__, retry);
                }
                while( !mrvl_sd8xxx_force_poweroff() && retry++ != 3 );
                bluetooth_disable();
            }
            else if( *iparam == BT_VND_PWR_OFF )
            {
                ALOGI("%s: power off", __func__);
                ret = bluetooth_disable();
                if( ret == 0 ) return 0;
                ALOGI("%s: Fail to disable BT, force power off", __func__);
                if( !mrvl_sd8xxx_force_poweroff() )
                    ret = 0;
            }
            return ret;

        case BT_VND_OP_FW_CFG       : 
            if( bt_vendor_cbacks != NULL )
            {
                bt_vendor_cbacks->fwcfg_cb(0);
            }
            break;

        case BT_VND_OP_SCO_CFG      : 
            ret = btsnd_hcic_set_pcm_voice_path();
            if( ret == 0 )
            {
                ret = btsnd_hcic_set_pcm_sync();
                if( ret == 0 )
                {
                    ret = btsnd_hcic_set_pcm_mode();
                    if( ret == 0 )
                    {
                        ret = btsnd_hcic_set_pcm_link();
                    }
                }
            }
            if( bt_vendor_cbacks != NULL )
                bt_vendor_cbacks->scocfg_cb(ret);
            break;

        case BT_VND_OP_USERIAL_OPEN : 
            bt_sock = open(BT_DEV_PATH, O_RDWR);
            if( bt_sock < 0 )
            {
                ALOGE("%s: open %s failed error = %s", __func__, BT_DEV_PATH, strerror(errno));
                ret = -1;
            }
            else
            {
                ALOGI("%s: open %s successfully", __func__, BT_DEV_PATH);
                iparam[0] = bt_sock;
                iparam[1] = bt_sock;
                iparam[2] = bt_sock;
                iparam[3] = bt_sock;
                ret = 1;
            }
            break;

        case BT_VND_OP_USERIAL_CLOSE: 
            ioctl(bt_sock, 0x4D01, &ret);
            usleep(1000);
            if( !bt_sock || close(bt_sock) == 0 )
                ret = 0;
            else
            {
                ALOGE("%s: error while closing bt_sock: %s", __func__, strerror(errno));
                return -1;
            }
            break;

        case BT_VND_OP_GET_LPM_IDLE_TIMEOUT:
            break;

        case BT_VND_OP_LPM_SET_MODE:
            if( bt_vendor_cbacks != NULL )
                bt_vendor_cbacks->lpm_cb(BT_VND_OP_RESULT_SUCCESS);
            break;

        case BT_VND_OP_LPM_WAKE_SET_STATE:
            break;

        case BT_VND_OP_SET_AUDIO_STATE:
            bt_set_sco_codec_cmd(param);
            break;

        case BT_VND_OP_EPILOG:
            if( bt_vendor_cbacks )
                bt_vendor_cbacks->epilog_cb(BT_VND_OP_RESULT_SUCCESS);
            break;

        default: return -1;
    }

    return ret;
}

/** Closes the interface */
static void bt_vnd_mrvl_if_cleanup( void )
{
}

// Entry point of DLib
const bt_vendor_interface_t BLUETOOTH_VENDOR_LIB_INTERFACE = {
    sizeof(bt_vendor_interface_t),
    bt_vnd_mrvl_if_init,
    bt_vnd_mrvl_if_op,
    bt_vnd_mrvl_if_cleanup,
    // MRVL Doesn't provide ssr_cleanup
    NULL,
};
