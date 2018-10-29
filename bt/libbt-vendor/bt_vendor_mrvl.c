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

#include <utils/Log.h>
#include <cutils/properties.h>
#include <fcntl.h>
#include "bt_vendor_lib.h"
#include "utils.h"
#include "marvell_wireless.h"

#define WAIT_TIMEOUT 200000

/******************************************************************************
**  Variables
******************************************************************************/
bt_vendor_callbacks_t *vnd_cb = NULL;
uint8_t bdaddr[6]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
int mchar_fd = -1;

static const char BT_DEV_PATH[] = "/dev/mbtchar0";
static const char BT_PCMMASTER_PROP[] = "persist.bt.pcmmaster";

#define HCI_CMD_MARVELL_WRITE_PCM_SETTINGS      0xFC07
#define HCI_CMD_MARVELL_SET_SCO_DATA_PATH       0xFC1D
#define HCI_CMD_MARVELL_WRITE_BD_ADDRESS        0xFC22
#define HCI_CMD_MARVELL_WRITE_PCM_SYNC_SETTINGS 0xFC28
#define HCI_CMD_MARVELL_WRITE_PCM_LINK_SETTINGS 0xFC29
#define HCI_CMD_MARVELL_SET_SCO_DATA_CODEC      0xFC73

/******************************************************************************
**  Local type definitions
******************************************************************************/


/******************************************************************************
**  Functions
******************************************************************************/
int btsnd_hcic_set_pcm_voice_path()
{
    HC_BT_HDR *p_buf;
    
    p_buf = (HC_BT_HDR*)vnd_cb->alloc(BT_HC_HDR_SIZE);
    if( p_buf == NULL )
        return 1;

    p_buf->event          = MSG_STACK_TO_HC_HCI_CMD;
    p_buf->len            = 6;
    p_buf->offset         = 0;
    p_buf->layer_specific = 0;
    p_buf->data[0]        = 29;
    p_buf->data[1]        = -4;
    p_buf->data[2]        = 1;
    p_buf->data[3]        = 1;
    if( !vnd_cb->xmit_cb(HCI_CMD_MARVELL_SET_SCO_DATA_PATH, p_buf, 0) )
    {
        vnd_cb->dealloc(p_buf);
        return 1;
    }
    return 0;
}

int btsnd_hcic_set_pcm_sync()
{
    char pcmmaster[PROP_VALUE_MAX];   
    int state;
    HC_BT_HDR *p_buf;

    property_get(BT_PCMMASTER_PROP, pcmmaster, "1");
    if( strcmp(pcmmaster, "0") == 0 )
        state = 0;
    else
        state = 3;

    p_buf = (HC_BT_HDR*)vnd_cb->alloc(BT_HC_HDR_SIZE+2);
    if( p_buf == NULL )
        return 1;

    p_buf->event          = MSG_STACK_TO_HC_HCI_CMD;
    p_buf->len            = 6;
    p_buf->offset         = 0;
    p_buf->layer_specific = 0;
    p_buf->data[0]        = 40;
    p_buf->data[1]        = -4;
    p_buf->data[2]        = 3;
    p_buf->data[3]        = 3;
    p_buf->data[4]        = 0;
    p_buf->data[5]        = state;

    if( !vnd_cb->xmit_cb(HCI_CMD_MARVELL_WRITE_PCM_SYNC_SETTINGS, p_buf, NULL) )
    {
        vnd_cb->dealloc(p_buf);
        return 1;
    }
    return 0;
}

int btsnd_hcic_set_pcm_mode()
{
    char pcmmaster[PROP_VALUE_MAX];
    int state;
    HC_BT_HDR *p_buf;
    property_get(BT_PCMMASTER_PROP, pcmmaster, "1");
    if( strcmp(pcmmaster, "0") == 0 )
        state = 0;
    else
        state = 2;

    p_buf = (HC_BT_HDR*)vnd_cb->alloc(BT_HC_HDR_SIZE);
    if( p_buf == NULL )
        return 1;

    p_buf->event          = MSG_STACK_TO_HC_HCI_CMD;
    p_buf->len            = 4;
    p_buf->offset         = 0;
    p_buf->layer_specific = 0;
    p_buf->data[0]        = 7;
    p_buf->data[1]        = -4;
    p_buf->data[2]        = 1;
    p_buf->data[3]        = state;
    if( !vnd_cb->xmit_cb(HCI_CMD_MARVELL_WRITE_PCM_SETTINGS, p_buf, NULL) )
    {
        vnd_cb->dealloc(p_buf);
        return 1;
    }
    return 0;
}

int btsnd_hcic_set_pcm_link()
{
    HC_BT_HDR *p_buf;

    p_buf = (HC_BT_HDR*)vnd_cb->alloc(BT_HC_HDR_SIZE+1);
    if( p_buf == NULL )
        return 1;

    p_buf->event          = MSG_STACK_TO_HC_HCI_CMD;
    p_buf->len            = 5;
    p_buf->offset         = 0;
    p_buf->layer_specific = 0;
    p_buf->data[0]        = 41;
    p_buf->data[1]        = -4;
    p_buf->data[2]        = 2;
    p_buf->data[3]        = 4;
    p_buf->data[4]        = 0;

    if( !vnd_cb->xmit_cb(HCI_CMD_MARVELL_WRITE_PCM_LINK_SETTINGS, p_buf, NULL) )
    {
        vnd_cb->dealloc(p_buf);
        return 1;
    }
    return 0;
}

void bt_set_sco_codec_cback(void *param)
{
    HC_BT_HDR* p_buf = (HC_BT_HDR*)param;
    uint8_t res = p_buf->data[5];
    uint16_t opcode;
    if( res )
        ALOGE("%s: Setting Codec Failed %d", __func__, res);
    else
    {
        opcode = p_buf->data[3] | (p_buf->data[4]<<8);
        ALOGI("%s: OpCode 0x%04x Status %d", __func__, opcode, res);
        vnd_cb->dealloc(p_buf);
    }
}

int bt_set_sco_codec_cmd(void *param)
{
    int *iparam = (int*)param;
    int codec = iparam[1];
    char *buf;
    int ret = 0;

    ALOGI("%s: Handle %d, codec %d, state %d", __func__, iparam[0], codec, iparam[2]);
    if( vnd_cb != NULL )
    {
        buf = vnd_cb->alloc(12);
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
            ret = vnd_cb->xmit_cb(HCI_CMD_MARVELL_SET_SCO_DATA_CODEC, buf, bt_set_sco_codec_cback);
            if( ret )
                return ret;
            vnd_cb->dealloc(buf);
        }
        ALOGI("%s: vendor lib postload aborted", __func__);
        vnd_cb->scocfg_cb(BT_VND_OP_RESULT_SUCCESS);
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

    vnd_cb = (bt_vendor_callbacks_t*)p_cb;
    memcpy(bdaddr, local_bdaddr, sizeof(bdaddr));

    ALOGI("%s: Local BD Address : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x", __func__,
           bdaddr[0], bdaddr[1], bdaddr[2], bdaddr[3], bdaddr[4], bdaddr[5]);
    return 0;
}

/** Requested operations */
static int bt_vnd_mrvl_if_op(bt_vendor_opcode_t opcode, void *param)
{
    int *power_state = (int*)param;
    int ret = 0;
    int retry = 1;

    switch( opcode )
    {
        case BT_VND_OP_POWER_CTRL: 
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
                while( !mrvl_sd8xxx_force_poweroff() && retry++ < 3 );
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

        case BT_VND_OP_FW_CFG: 
            if( vnd_cb != NULL )
                vnd_cb->fwcfg_cb(0);
            break;

        case BT_VND_OP_SCO_CFG: 
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
            if( vnd_cb != NULL )
                vnd_cb->scocfg_cb(ret);
            break;

        case BT_VND_OP_USERIAL_OPEN : 
            mchar_fd = open(BT_DEV_PATH, O_RDWR);
            if( mchar_fd < 0 )
            {
                ALOGE("%s: open %s failed error = %s", __func__, BT_DEV_PATH, strerror(errno));
                ret = -1;
            }
            else
            {
                ALOGI("%s: open %s successfully", __func__, BT_DEV_PATH);
                iparam[0] = mchar_fd;
                iparam[1] = mchar_fd;
                iparam[2] = mchar_fd;
                iparam[3] = mchar_fd;
                ret = 1;
            }
            break;

        case BT_VND_OP_USERIAL_CLOSE: 
            ioctl(mchar_fd, 0x4D01, &ret);
            usleep(1000);
            if( !mchar_fd || close(mchar_fd) == 0 )
                ret = 0;
            else
            {
                ALOGE("%s: error while closing mchar_fd: %s", __func__, strerror(errno));
                return -1;
            }
            break;

        case BT_VND_OP_GET_LPM_IDLE_TIMEOUT:
            break;

        case BT_VND_OP_LPM_SET_MODE:
            if( vnd_cb != NULL )
                vnd_cb->lpm_cb(BT_VND_OP_RESULT_SUCCESS);
            break;

        case BT_VND_OP_LPM_WAKE_SET_STATE:
            break;

        case BT_VND_OP_SET_AUDIO_STATE:
            bt_set_sco_codec_cmd(param);
            break;

        case BT_VND_OP_EPILOG:
            if( vnd_cb )
                vnd_cb->epilog_cb(BT_VND_OP_RESULT_SUCCESS);
            break;

        default: return -1;
    }

    return ret;
}

/** Closes the interface */
static void bt_vnd_mrvl_if_cleanup( void )
{
    return;
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
