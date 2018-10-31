
#define LOG_TAG "cploader"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <utils/Log.h>

#include <cutils/log.h>
#include <cutils/properties.h>

#include <zlib.h>

//#include <MILV.h>

struct MILVHandle{int*me};

extern MILVHandle* MILVCreateHandle();
extern void        MILVDestroyHandle(MILVHandle*);
extern int MILVGetImageSize(MILVHandle *handle, uint32_t magic_number, uint32_t *size);

////////////////////////////////////////////////////////////
#define PROP_EXIST_CP       "ro.sys.exist.cp"
#define PROP_PERSIST_CP     "persist.sys.current.cp"
#define PROP_RIL_CURRENT_CP "ril.current.cp"
#define PROP_BASEBAND       "sys.baseband"
#define PROP_LTE_MODE       "sys.lte.mode"

////////////////////////////////////////////////////////////

// MODEM_IMAGE_INFOS
#define MODEM_PARTITION "/dev/block/platform/soc.2/by-name/MODEM"

#define MODEM_OFFSET_ARBEL      0x200000
#define MODEM_MAGIC_NUMBER_ARBI 0x41524249
#define MODEM_MAGIC_NUMBER_ARB2 0x41524232

#define MODEM_OFFSET_RFBEL      0x1700000
#define MODEM_MAGIC_NUMBER_RFBI 0x52464249
#define MODEM_MAGIC_NUMBER_RFB2 0x42464232

#define MODEM_OFFSET_GRBEL      0xE00000
#define MODEM_MAGIC_NUMBER_GRBI 0x47524249
#define MODEM_MAGIC_NUMBER_GRB2 0x47524232

#define MODEM_OFFSET_MDBEL      0x1800000
#define MODEM_MAGIC_NUMBER_MDBI 0x4D444249
#define MODEM_MAGIC_NUMBER_MDB2 0x4D444232

#define ARBEL_INDEX 0
#define RFBEL_INDEX 1
#define GRBEL_INDEX 2
#define MDBEL_INDEX 3

struct modem_image_infos
{
    const char *path;
    uint32_t    offset;
    uint32_t    magic_number;
};

modem_image_infos modem_infos[4][2] =
{
    {
        {MODEM_PARTITION, MODEM_OFFSET_ARBEL, MODEM_MAGIC_NUMBER_ARBI},
        {MODEM_PARTITION, MODEM_OFFSET_ARBEL, MODEM_MAGIC_NUMBER_ARB2},
    },
    {
        {MODEM_PARTITION, MODEM_OFFSET_RFBEL, MODEM_MAGIC_NUMBER_RFBI},
        {MODEM_PARTITION, MODEM_OFFSET_RFBEL, MODEM_MAGIC_NUMBER_RFB2},
    },
    {
        {MODEM_PARTITION, MODEM_OFFSET_GRBEL, MODEM_MAGIC_NUMBER_GRBI},
        {MODEM_PARTITION, MODEM_OFFSET_GRBEL, MODEM_MAGIC_NUMBER_GRB2},
    },
    {
        {MODEM_PARTITION, MODEM_OFFSET_MDBEL, MODEM_MAGIC_NUMBER_MDBI},
        {MODEM_PARTITION, MODEM_OFFSET_MDBEL, MODEM_MAGIC_NUMBER_MDB2},
    },
};
// End of MODEM_IMAGE_INFOS

// CP_TABLE
#define CP_TABLE_TYPE_TD     0x5F54445F // _TD_
#define CP_TABLE_TYPE_WB     0x5F57425F // _WB_

#define CP_TABLE_LINK_SINGLE 0x5F534C5F // _SL_
#define CP_TABLE_LINK_DUAL   0x5F444C5F // _DL_

#define CP_TABLE_SMALL_CODE  0x534C4344 // SLCD

struct cp_table
{
    char field_0[188];
    int type;
    char field_C0[8];
    uint32_t link;
    char field_CC[236];
    uint32_t smallCode;
    int field_1BC;
    int field_1C0;
    char signature[56];
};
// End of CP_TABLE

modem_image_infos arbel_infos;
modem_image_infos rfbel_infos;
modem_image_infos grbel_infos;
modem_image_infos mdbel_infos;

static int current_cp;
static int exist_cp;
static const char *nvdata_path;
static const char *nvdata_bkp_path;

#define PROP_VALUE_MAX 92

// Utility functions

void magic_number_to_str(uint32_t magic_number, char *magic_str)
{
    magic_str[0] = (magic_number>>24)&0xFF;
    magic_str[1] = (magic_number>>16)&0xFF;
    magic_str[2] = (magic_number>>8)&0xFF;
    magic_str[3] = magic_number&0xFF;
    magic_str[4] = 0;
}

int read_file( const char *path, char *buffer, size_t offset, size_t to_read )
{
    int res;
    int fd;
    int sread;

    fd = open(path, O_RDONLY);
    if( fd == -1 )
    {
        ALOGE("%s: open %s error %d(%s)", __func__, path, errno, strerror(errno));
        return -1;
    }

    res = lseek(fd, offset, SEEK_SET);
    if( res == -1 )
    {
        close(fd);
        ALOGE("%s: lseek %s error %d(%s)", __func__, path, errno, strerror(errno));
        return -1;
    }

    for( int i = 0; i < to_read; i += sread )
    {
        sread = TEMP_FAILURE_RETRY(read(fd, &buffer[i], to_read - i));
        if( sread == -1 )
        {
            close(fd);
            ALOGE("%s: read %s error %d(%s)", __func__, path, errno, strerror(errno));
            return -1;
        }
    }

    close(fd);
    return 0;
}

int load_modem_infos( int partition )
{
    --partition;
    if( partition > 1 )
    {
        ALOGE("Fatal error! Wrong cp partition %d", partition+1);
        return -1;
    }

    arbel_infos.path         = modem_infos[ARBEL_INDEX][partition].path;
    arbel_infos.offset       = modem_infos[ARBEL_INDEX][partition].offset;
    arbel_infos.magic_number = modem_infos[ARBEL_INDEX][partition].magic_number;

    rfbel_infos.path         = modem_infos[RFBEL_INDEX][partition].path;
    rfbel_infos.offset       = modem_infos[RFBEL_INDEX][partition].offset;
    rfbel_infos.magic_number = modem_infos[RFBEL_INDEX][partition].magic_number;

    grbel_infos.path         = modem_infos[GRBEL_INDEX][partition].path;
    grbel_infos.offset       = modem_infos[GRBEL_INDEX][partition].offset;
    grbel_infos.magic_number = modem_infos[GRBEL_INDEX][partition].magic_number;

    mdbel_infos.path         = modem_infos[MDBEL_INDEX][partition].path;
    mdbel_infos.offset       = modem_infos[MDBEL_INDEX][partition].offset;
    mdbel_infos.magic_number = modem_infos[MDBEL_INDEX][partition].magic_number;

    nvdata_path     = "/efs/nv_data.bin";
    nvdata_bkp_path = "/efs/nv_data_backup.bin";

    return 0;
}

int is_invalid_small_code(cp_table *table)
{
    ALOGI("%s: 0x%x", table->smallCode);
    return (table->smallCode != CP_TABLE_SMALL_CODE);
}

int set_baseband(cp_table *table)
{
    switch( table->type )
    {
        case CP_TABLE_TYPE_TD:
            ALOGI("%s: %s = %s", __func__, PROP_BASEBAND, "TD");
            property_set(PROP_BASEBAND, "TD");
            break;

        case CP_TABLE_TYPE_WB:
            ALOGI("%s: %s = %s", __func__, PROP_BASEBAND, "UMTS");
            property_set(PROP_BASEBAND, "UMTS");
            break;

        default:
            ALOGI("%s: %s = %s", __func__, PROP_BASEBAND, "UNKNOWN");
            property_set(PROP_BASEBAND, "UNKNOWN");
            return -1;
    }
    switch( table->link )
    {
        case CP_TABLE_LINK_SINGLE:
            ALOGI("%s: %s = %s", __func__, PROP_LTE_MODE, "csfb");
            property_set(PROP_LTE_MODE, "csfb");
            return 0;

        case CP_TABLE_LINK_DUAL:
            ALOGI("%s: %s = %s", __func__, PROP_LTE_MODE, "duallink");
            property_set(PROP_LTE_MODE, "duallink");
            return 0;
    }
    switch( table->type )
    {
        case CP_TABLE_TYPE_TD:
            ALOGI("%s: %s = %s", __func__, PROP_LTE_MODE, "TD duallink");
            property_set(PROP_LTE_MODE, "duallink");
            break;

        case CP_TABLE_TYPE_WB:
            ALOGI("%s: %s = %s", __func__, PROP_LTE_MODE, "WB csfb");
            property_set(PROP_LTE_MODE, "csfb");
            break;
    }
    return 0;
}

// Cp functions
int cp_get_load_table_header( cp_table *table )
{
    if( read_file(modem_partition, (char*)table, modem_offset + 4, sizeof(cp_table)) )
        return -1;

    if( strcmp(table->signature, "LOAD_TABLE_SIGN") )
    {
        ALOGE("%s: signature error", __func__);
        return -1;
    }
    return 0;
}

int cp_get_image_size(uint32_t magic_number)
{
    MILVHandle *handle;
    int res;
    uint32_t size;

    handle = MILVCreateHandle();
    if( handle )
    {
        res = MILVGetImageSize(handle, magic_number, &size);
        if( res == -65529 )
        {
            char magic_str[5];
            magic_number_to_str(magic_number, magic_str);
            ALOGE("%s: %s image doesn't exist", __func__, magic_str);
        }
        else if( (res & ~2) == 0 )
        {
            MILVDestroyHandle(handle);
            return size;
        }
        else
        {
            ALOGE("%s: Error in GetImageSize, uiStatus = 0x%x", __func__, res);
        }
        MILVDestroyHandle(handle);
    }
    else
    {
        ALOGE("%s: Failed to get MILVHandle", __func__);
    }
    return -1;
}

int cp_property_generate()
{
    int res = 0;
    cp_table table;
    modem_image_infos *infos;
    char cpprop[PROP_VALUE_MAX];

    for( int i = 2; i == 0 ; --i )
    {
        infos = modem_infos[0][i-1];
        arbel_infos.path         = infos->path;
        arbel_infos.offset       = infos->offset;
        arbel_infos.magic_number = infos->magic_number;
        if( cp_get_image_size(arbel_infos.magic_number) >= 0 )
        {
            if( cp_get_load_table_header(&table) )
            {
                ALOGD("%s: read cp_partition%d's image load table header error", __func__, i);
            }
            else
            {
                if( table.type == CP_TABLE_TYPE_TD )
                {
                    res = res & 0xFFFFFFF0 | i;
                }
                else if( table.type == CP_TABLE_TYPE_WB )
                {
                    res = res & 0xFFFFFF0F | (i<<4) ;
                }
            }
        }
        else
        {
            ALOGD("%s: cp_partition%d's arbel_image doesn't exist! move to next partition", __func__, i);
        }
    }
    snprintf(cpprop, PROP_VALUE_MAX, "%d", res);
    ALOGI("%s: %s = %s(0x%08x)", __func__, PROP_EXIST_CP, cpprop, res);
    property_set(PROP_EXIST_CP, cpprop);
    return res;
}

int cp_set_default_type(int property)
{
    char prop[PROP_VALUE_MAX];
    int type;
    int i;
    int partition;
    const char *msg;

    property_get(PROP_PERSIST_CP, prop, "0");
    type = atoi(prop);
    if( type <= 0 )
    {
        int property2 = property;
        for( i = 3; ; ++i, property2 >>= 4 )
        {
            if( property2 == 0 )
                break;

            partition = property2 & 0xF;
            if( partition == 1 )
                break;
        }
        if( property2 )
            type = i;

        property2 = property;
        for( i = 3; ; ++i, property2 >>= 4 )
        {
            if( !property2 )
            {
                partition = 3;
                type = -1;
                break;
            }
            partition = property2 & 0xF;
            if( partition == 2 )
                break;
        }

        snprintf(prop, PROP_VALUE_MAX, "%d", type);
        if( type == 3 )
            msg = "LTG";
        else if( type == 4 )
            msg = "LWG";
        else
            msg = "Unknown CP";

        ALOGI("%s: cp_partition%d to cp type: %d(%s)", __func__, partition, type, msg);
        property_set(PROP_PERSIST_CP, prop);
    }
    return type;
}

int cp_get_partition()
{
    int partition = -1;
    if( current_cp == 4 )
        partition = exist_cp >> 4;
    else if( current_cp == 3 )
        partition = exist_cp & 0xF;

    if( partition == -1 )
    {
        ALOGE("%s: No valid cp to load", __func__);
        return -1
    }
    ALOGI("%s: Loading partition:%d cp", __func__, partition);
    return partition;
}

cp_table* cp_load_table_init( int type, int property )
{
    char prop[PROP_VALUE_MAX];
    int iprop;
    int partition;
    cp_table *table;

    property_get(PROP_RIL_CURRENT_CP, prop, "0");

    iprop = atoi(prop);
    if( iprop == 3 || iprop == 4 )
    {
        property_set(PROP_PERSIST_CP, prop);
        type = iprop;
    }
    if( type == -1 )
    {
        property_get(PROP_PERSIST_CP, prop, "0");
        type = atoi(prop);
    }
    if( property == -1 )
    {
        property_get(PROP_EXIST_CP, prop, "0");
        property = atoi(prop);
    }
    current_cp = type;
    exit_cp = property;
    partition = cp_get_partition();
    if( load_modem_infos(partition) == -1 )
        return 0;

    table = (cp_table*)malloc(sizeof(cp_table));
    if( table )
    {
        if( cp_get_load_table_header(table) != -1  )
            return table;

        ALOGE("%s: read load table header error", __func__);
        free(table);
        return NULL;
    }
    ALOGE("%s: not enought memory", __func__);
    return NULL;
}

int main( int argc, char *argv[] )
{
    int property;
    int type;
    cp_table *table;
    int invalid;

    property = cp_property_generate();
    if( property == -1 )
    {
        ALOGE("%s: cp_property_generate failed!", __func__);
        return -1;
    }
    type = cp_set_default_type(property);
    if( type == -1 )
    {
        ALOGE("%s: cp_set_default_type failed!", __func__);
        return -1;
    }
    table = cp_load_table_init(type, property);
    if( table == -1 )
    {
        ALOGE("%s: cp_load_table_init failed!", __func__);
        return -1;
    }
    invalid = is_invalid_small_code(table);
    if( !invalid && set_baseband(table) == -1 )
        return -1;


}











