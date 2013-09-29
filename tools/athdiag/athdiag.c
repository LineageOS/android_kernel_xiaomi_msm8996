/*
 * Copyright (c) 2013, The Linux Foundation. All rights reserved.
 *
 * Previously licensed under the ISC license by Qualcomm Atheros, Inc.
 *
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This file was originally distributed by Qualcomm Atheros, Inc.
 * under proprietary terms before Copyright ownership was assigned
 * to the Linux Foundation.
 */


#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <linux/version.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#include <athdefs.h>
#include <a_types.h>

#include "apb_athr_wlan_map.h"
#include "rtc_soc_reg.h"
#include "efuse_reg.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

/*
 * This is a user-level agent which provides diagnostic read/write
 * access to Target space.  This may be used
 *   to collect information for analysis
 *   to read/write Target registers
 *   etc.
 */

#define DIAG_READ_TARGET      1
#define DIAG_WRITE_TARGET     2
#define DIAG_READ_WORD        3
#define DIAG_WRITE_WORD       4

#define ADDRESS_FLAG                    0x001
#define LENGTH_FLAG                     0x002
#define PARAM_FLAG                      0x004
#define FILE_FLAG                       0x008
#define UNUSED0x010                     0x010
#define AND_OP_FLAG                     0x020
#define BITWISE_OP_FLAG                 0x040
#define QUIET_FLAG                      0x080
#define OTP_FLAG                        0x100
/* dump file mode,x: hex mode; other binary mode. */
#define HEX_FLAG                        0x200
#define UNUSED0x400                     0x400
#define DEVICE_FLAG                     0x800

/* Limit malloc size when reading/writing file */
#define MAX_BUF                         (8*1024)

unsigned int flag;
const char *progname;
const char commands[] =
"commands and options:\n\
--get --address=<target word address>\n\
--set --address=<target word address> --[value|param]=<value>\n\
                                      --or=<OR-ing value>\n\
                                      --and=<AND-ing value>\n\
--read --address=<target address> --length=<bytes> --file=<filename>\n\
--write --address=<target address> --file=<filename>\n\
                                   --[value|param]=<value>\n\
--otp --read --address=<otp offset> --length=<bytes> --file=<filename>\n\
--otp --write --address=<otp offset> --file=<filename>\n\
--quiet\n\
--device=<device name> (if not default)\n\
The options can also be given in the abbreviated form --option=x or -o x.\n\
The options can be given in any order.";

#define A_ROUND_UP(x, y)             ((((x) + ((y) - 1)) / (y)) * (y))

#define quiet() (flag & QUIET_FLAG)
#define nqprintf(args...) if (!quiet()) {printf(args);}
#define min(x,y) ((x) < (y) ? (x) : (y))

void ReadTargetRange(int dev, A_UINT32 address, A_UINT8 *buffer,
                     A_UINT32 length);
void ReadTargetWord(int dev, A_UINT32 address, A_UINT32 *buffer);
void WriteTargetRange(int dev, A_UINT32 address, A_UINT8 *buffer,
                      A_UINT32 length);
void WriteTargetWord(int dev, A_UINT32 address, A_UINT32 value);
int ValidWriteOTP(int dev, A_UINT32 address, A_UINT8 *buffer, A_UINT32 length);

static inline void *
MALLOC(int nbytes)
{
    void *p= malloc(nbytes);

    if (!p)
    {
        fprintf(stderr, "err -Cannot allocate memory\n");
    }

    return p;
}

void
usage(void)
{
    fprintf(stderr, "usage:\n%s ", progname);
    fprintf(stderr, "%s\n", commands);
    exit(-1);
}

void
ReadTargetRange(int dev, A_UINT32 address, A_UINT8 *buffer, A_UINT32 length)
{
    int nbyte;
    unsigned int remaining;

    (void)lseek(dev, address, SEEK_SET);

    remaining = length;
    while (remaining) {
        nbyte = read(dev, buffer, (size_t)remaining);
        if (nbyte <= 0) {
            fprintf(stderr, "err %s failed (nbyte=%d, address=0x%x"
                    " remaining=%d).\n",
                    __FUNCTION__, nbyte, address, remaining);
            exit(1);
        }

        remaining -= nbyte;
        buffer += nbyte;
        address += nbyte;
    }
}

void
ReadTargetWord(int dev, A_UINT32 address, A_UINT32 *buffer)
{
    ReadTargetRange(dev, address, (A_UINT8 *)buffer, sizeof(*buffer));
}

void
ReadTargetOTP(int dev, A_UINT32 offset, A_UINT8 *buffer, A_UINT32 length)
{
    A_UINT32 status_mask;
    A_UINT32 otp_status, i;

    /* Enable OTP reads */
    WriteTargetWord(dev, RTC_SOC_BASE_ADDRESS+OTP_OFFSET, OTP_VDD12_EN_SET(1));
    status_mask = OTP_STATUS_VDD12_EN_READY_SET(1);
    do {
        ReadTargetWord(dev, RTC_SOC_BASE_ADDRESS+OTP_STATUS_OFFSET,
                       &otp_status);
    } while ((otp_status & OTP_STATUS_VDD12_EN_READY_MASK) != status_mask);

    /* Conservatively set OTP read timing */
    WriteTargetWord(dev, EFUSE_BASE_ADDRESS+RD_STROBE_PW_REG_OFFSET, 6);

    /* Read data from OTP */
    for (i=0; i<length; i++, offset++) {
        A_UINT32 efuse_word;

        ReadTargetWord(dev, EFUSE_BASE_ADDRESS+EFUSE_INTF0_OFFSET+(offset<<2),
                       &efuse_word);
        buffer[i] = (A_UINT8)efuse_word;
    }

    /* Disable OTP */
    WriteTargetWord(dev, RTC_SOC_BASE_ADDRESS+OTP_OFFSET, 0);
}

void
WriteTargetRange(int dev, A_UINT32 address, A_UINT8 *buffer, A_UINT32 length)
{
    int nbyte;
    unsigned int remaining;
    A_UINT8 *tbuffer = NULL;

    fprintf(stderr, "add 0x%x buff 0x%x\n", address, *((A_UINT32 *)buffer));
    remaining = sizeof(address) + length;
    while (remaining > sizeof(address)) {
        tbuffer = (A_UINT8 *)MALLOC(remaining);
        memcpy(tbuffer, (A_UINT8 *)(&address), sizeof(address));
        memcpy(tbuffer + sizeof(address), buffer, remaining - sizeof(address));
        nbyte = write(dev, tbuffer, (size_t)remaining);
        if (nbyte <= 0) {
            fprintf(stderr, "err %s failed (nbyte=%d, address=0x%x"
                    " remaining=%d).\n",
                    __FUNCTION__, nbyte, address, remaining);
            exit(1);
        }

        remaining -= nbyte;
        buffer += nbyte;
        address += nbyte;
        free(tbuffer);
    }
}

void
WriteTargetWord(int dev, A_UINT32 address, A_UINT32 value)
{
    A_UINT32 param = value;

    WriteTargetRange(dev, address, (A_UINT8 *)&param, sizeof(param));
}

#define BAD_OTP_WRITE(have, want) ((((have) ^ (want)) & (have)) != 0)

/*
 * Check if the current contents of OTP and the desired
 * contents specified by buffer/length are compatible.
 * If we're trying to CLEAR an OTP bit, then this request
 * is invalid.
 * returns: 0-->INvalid; 1-->valid
 */
int
ValidWriteOTP(int dev, A_UINT32 offset, A_UINT8 *buffer, A_UINT32 length)
{
    A_UINT32 i;
    A_UINT8 *otp_contents;

    otp_contents = (A_UINT8 *)MALLOC(length);
    ReadTargetOTP(dev, offset, otp_contents, length);

    for (i=0; i<length; i++) {
        if (BAD_OTP_WRITE(otp_contents[i], buffer[i])) {
            fprintf(stderr, "Abort. Cannot change offset %d from 0x%02x"
                    " to 0x%02x\n",
                    offset+i, otp_contents[i], buffer[i]);
            return 0;
        }
    }

    return 1;
}

/*
 * This is NOT the ideal way to write OTP since it does not handle
 * media errors.  It's much better to use the otpstream_* API.
 * This capability is here to help salvage parts that have previously
 * had OTP written.
 */
void
WriteTargetOTP(int dev, A_UINT32 offset, A_UINT8 *buffer, A_UINT32 length)
{
    A_UINT32 status_mask;
    A_UINT32 otp_status, i;

    /* Enable OTP read/write power */
    WriteTargetWord(dev, RTC_SOC_BASE_ADDRESS+OTP_OFFSET,
                    OTP_VDD12_EN_SET(1) | OTP_LDO25_EN_SET(1));
    status_mask = OTP_STATUS_VDD12_EN_READY_SET(1) |
                  OTP_STATUS_LDO25_EN_READY_SET(1);
    do {
        ReadTargetWord(dev, RTC_SOC_BASE_ADDRESS+OTP_STATUS_OFFSET,
                       &otp_status);
    } while ((otp_status & (OTP_STATUS_VDD12_EN_READY_MASK|
              OTP_STATUS_LDO25_EN_READY_MASK)) != status_mask);

    /* Conservatively set OTP read/write timing for 110MHz core clock */
    WriteTargetWord(dev, EFUSE_BASE_ADDRESS+VDDQ_SETTLE_TIME_REG_OFFSET, 2200);
    WriteTargetWord(dev, EFUSE_BASE_ADDRESS+PG_STROBE_PW_REG_OFFSET, 605);
    WriteTargetWord(dev, EFUSE_BASE_ADDRESS+RD_STROBE_PW_REG_OFFSET, 6);

    /* Enable eFuse for write */
    WriteTargetWord(dev, EFUSE_BASE_ADDRESS+EFUSE_WR_ENABLE_REG_OFFSET,
                    EFUSE_WR_ENABLE_REG_V_SET(1));
    WriteTargetWord(dev, EFUSE_BASE_ADDRESS+BITMASK_WR_REG_OFFSET, 0x00);

    /* Write data to OTP */
    for (i=0; i<length; i++, offset++) {
        A_UINT32 efuse_word;
        A_UINT32 readback;
        int attempt;

#define EFUSE_WRITE_COUNT 3
        efuse_word = (A_UINT32)buffer[i];
        for (attempt=1; attempt<=EFUSE_WRITE_COUNT; attempt++) {
            WriteTargetWord(dev,
                            EFUSE_BASE_ADDRESS+EFUSE_INTF0_OFFSET+(offset<<2),
                            efuse_word);
        }

        /* verify */
        ReadTargetWord(dev, EFUSE_BASE_ADDRESS+EFUSE_INTF0_OFFSET+(offset<<2),
                       &readback);
        if (efuse_word != readback) {
            fprintf(stderr, "OTP write failed. Offset=%d, Value=0x%x,"
                    " Readback=0x%x\n", offset, efuse_word, readback);
            break;
        }
    }

    /* Disable OTP */
    WriteTargetWord(dev, RTC_SOC_BASE_ADDRESS+OTP_OFFSET, 0);
}

unsigned int
parse_address(char *optarg)
{
    unsigned int address;

    /* may want to add support for symbolic addresses here */

    address = strtoul(optarg, NULL, 0);

    return address;
}

int
main (int argc, char **argv) {
    int c, fd, dev;
    int i;
    FILE * dump_fd;
    unsigned int address = 0, length = 0;
    A_UINT32 param;
    char filename[PATH_MAX];
    char devicename[PATH_MAX];
    unsigned int cmd = 0;
    A_UINT8 *buffer;
    unsigned int bitwise_mask = 0;
    progname = argv[0];

    if (argc == 1) usage();

    flag = 0;
    memset(filename, '\0', sizeof(filename));
    memset(devicename, '\0', sizeof(devicename));

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"address", 1, NULL, 'a'},
            {"and", 1, NULL, 'n'},
            {"device", 1, NULL, 'D'},
            {"get", 0, NULL, 'g'},
            {"file", 1, NULL, 'f'},
            {"length", 1, NULL, 'l'},
            {"or", 1, NULL, 'o'},
            {"otp", 0, NULL, 'O'},
            {"param", 1, NULL, 'p'},
            {"quiet", 0, NULL, 'q'},
            {"read", 0, NULL, 'r'},
            {"set", 0, NULL, 's'},
            {"value", 1, NULL, 'p'},
            {"write", 0, NULL, 'w'},
            {"hex", 0, NULL, 'x'},
            {0, 0, 0, 0}
        };

        c = getopt_long (argc, argv, "xrwgsqOf:l:a:p:c:n:o:D:",
                         long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'r':
            cmd = DIAG_READ_TARGET;
            break;

        case 'w':
            cmd = DIAG_WRITE_TARGET;
            break;

        case 'g':
            cmd = DIAG_READ_WORD;
            break;

        case 's':
            cmd = DIAG_WRITE_WORD;
            break;

        case 'f':
            memset(filename, '\0', sizeof(filename));
            snprintf(filename, sizeof(filename), "%s", optarg);
            flag |= FILE_FLAG;
            break;

        case 'l':
            length = parse_address(optarg);
            flag |= LENGTH_FLAG;
            break;

        case 'a':
            address = parse_address(optarg);
            flag |= ADDRESS_FLAG;
            break;

        case 'p':
            param = strtoul(optarg, NULL, 0);
            flag |= PARAM_FLAG;
            break;

        case 'n':
            flag |= PARAM_FLAG | AND_OP_FLAG | BITWISE_OP_FLAG;
            bitwise_mask = strtoul(optarg, NULL, 0);
            break;

        case 'o':
            flag |= PARAM_FLAG | BITWISE_OP_FLAG;
            bitwise_mask = strtoul(optarg, NULL, 0);
            break;

        case 'O':
            flag |= OTP_FLAG;
            break;

        case 'q':
            flag |= QUIET_FLAG;
            break;

        case 'D':
            snprintf(devicename, sizeof(devicename), "%s%s", optarg,
                     "/athdiag");
            flag |= DEVICE_FLAG;
            break;

        case 'x':
            flag |= HEX_FLAG;
            break;

        default:
            fprintf(stderr, "Cannot understand '%s'\n", argv[option_index]);
            usage();
        }
    }

    for (;;) {
        /* DIAG uses a sysfs special file which may be auto-detected */
        if (!(flag & DEVICE_FLAG)) {
            FILE *find_dev;
            size_t nbytes;
            /*
             * Convenience: if no device was specified on the command
             * line, try to figure it out.  Typically there's only a
             * single device anyway.
             */
            find_dev = popen("find /proc -name athdiagpfs | head -1", "r");
            if (find_dev) {
                nbytes=fread(devicename, 1, sizeof(devicename), find_dev);
                pclose(find_dev);

                if (nbytes > 15) {
                    /* auto-detect possibly successful */
                    devicename[nbytes-1]='\0'; /* replace \n with 0 */
                } else {
                    snprintf(devicename, sizeof(devicename), "%s",
                             "unknown_DIAG_device");
                }
            }
        }

        dev = open(devicename, O_RDWR);
        if (dev >= 0) {
            break; /* successfully opened diag special file */
        } else {
            fprintf(stderr, "err %s failed (%d) to open DIAG file (%s)\n",
                __FUNCTION__, errno, devicename);
            exit(1);
        }
    }

    switch(cmd)
    {
    case DIAG_READ_TARGET:
        if ((flag & (ADDRESS_FLAG | LENGTH_FLAG | FILE_FLAG)) ==
                (ADDRESS_FLAG | LENGTH_FLAG | FILE_FLAG))
        {
            if (((int)(dump_fd = fopen(filename, "wb+"))) < 0)
            {
                fprintf(stderr, "err %s cannot create/open output file (%s)\n",
                        __FUNCTION__, filename);
                exit(1);
            }

            buffer = (A_UINT8 *)MALLOC(MAX_BUF);

            nqprintf(
                    "DIAG Read Target (address: 0x%x, length: %d,"
                    " filename: %s)\n", address, length, filename);
            {
                unsigned int remaining = length;

                if(flag & HEX_FLAG)
                {
                    if (flag & OTP_FLAG) {
                        fprintf(dump_fd,"target otp dump area"
                                " [0x%08x - 0x%08x]",address,address+length);
                    } else {
                        fprintf(dump_fd,"target mem dump area"
                                " [0x%08x - 0x%08x]",address,address+length);
                    }
                }
                while (remaining)
                {
                    length = (remaining > MAX_BUF) ? MAX_BUF : remaining;
                    if (flag & OTP_FLAG) {
                        ReadTargetOTP(dev, address, buffer, length);
                    } else {
                        ReadTargetRange(dev, address, buffer, length);
                    }
                    if(flag & HEX_FLAG)
                    {
                        for(i=0;i<(int)length;i+=4)
                        {
                            if(i%16 == 0)
                                fprintf(dump_fd,"\n0x%08x:\t",address+i);
                            fprintf(dump_fd,"0x%08x\t",*(A_UINT32*)(buffer+i));
                        }
                    }
                    else
                    {
                        fwrite(buffer,1 , length, dump_fd);
                    }
                    remaining -= length;
                    address += length;
                }
            }
            fclose(dump_fd);
            free(buffer);
        } else {
            usage();
        }
        break;

    case DIAG_WRITE_TARGET:
        if (!(flag & ADDRESS_FLAG))
        {
            usage(); /* no address specified */
        }
        if (!(flag & (FILE_FLAG | PARAM_FLAG)))
        {
            usage(); /* no data specified */
        }
        if ((flag & FILE_FLAG) && (flag & PARAM_FLAG))
        {
            usage(); /* too much data specified */
        }

        if (flag & FILE_FLAG)
        {
            struct stat filestat;
            unsigned int file_length;

            if ((fd = open(filename, O_RDONLY)) < 0)
            {
                fprintf(stderr, "err %s Could not open file"
                        " (%s)\n", __FUNCTION__, filename);
                exit(1);
            }
            memset(&filestat, '\0', sizeof(struct stat));
            buffer = (A_UINT8 *)MALLOC(MAX_BUF);
            fstat(fd, &filestat);
            file_length = filestat.st_size;
            if (file_length == 0) {
                fprintf(stderr, "err %s Zero length input file"
                        " (%s)\n", __FUNCTION__, filename);
                exit(1);
            }

            if (flag & LENGTH_FLAG) {
                if (length > file_length) {
                    fprintf(stderr, "err %s file %s: length (%d)"
                            " too short (%d)\n", __FUNCTION__,
                        filename, file_length, length);
                    exit(1);
                }
            } else {
                length = file_length;
            }

            nqprintf(
                 "DIAG Write Target (address: 0x%x, filename: %s,"
                 " length: %d)\n", address, filename, length);

        }
        else
        { /* PARAM_FLAG */
            nqprintf(
                 "DIAG Write Word (address: 0x%x, value: 0x%x)\n",
                  address, param);
            length = sizeof(param);
            buffer = (A_UINT8 *)&param;
            fd = -1;
        }

        /*
         * Write length bytes of data to memory/OTP.
         * Data is either present in buffer OR
         * needs to be read from fd in MAX_BUF chunks.
         *
         * Within the kernel, the implementation of
         * DIAG_WRITE_TARGET further limits the size
         * of each transfer over the interconnect.
         */
        {
            unsigned int remaining;
            unsigned int otp_check_address = address;

            if (flag & OTP_FLAG) {
                /* Validate OTP write before committing anything */
                remaining = length;
                while (remaining)
                {
                    int nbyte;

                    length = (remaining > MAX_BUF) ? MAX_BUF : remaining;
                    if (fd > 0)
                    {
                        nbyte = read(fd, buffer, length);
                        if (nbyte != (int)length) {
                            fprintf(stderr, "err %s read from file failed"
                                    " (%d)\n", __FUNCTION__, nbyte);
                            exit(1);
                        }
                    }

                    if ((flag & OTP_FLAG) && !ValidWriteOTP(dev,
                                otp_check_address, buffer, length))
                    {
                            exit(1);
                    }

                    remaining -= length;
                    otp_check_address += length;
                }
                (void)lseek(fd, 0, SEEK_SET);
            }

            remaining = length;
            while (remaining)
            {
                int nbyte;

                length = (remaining > MAX_BUF) ? MAX_BUF : remaining;
                if (fd > 0)
                {
                    nbyte = read(fd, buffer, length);
                    if (nbyte != (int)length) {
                        fprintf(stderr, "err %s read from file failed"
                                " (%d)\n", __FUNCTION__, nbyte);
                        exit(1);
                    }
                }

                if (flag & OTP_FLAG) {
                    WriteTargetOTP(dev, address, buffer, length);
                } else {
                    WriteTargetRange(dev, address, buffer, length);
                }

                remaining -= length;
                address += length;
            }
        }

        if (flag & FILE_FLAG) {
            free(buffer);
            close(fd);
        }

        break;

    case DIAG_READ_WORD:
        if ((flag & (ADDRESS_FLAG)) == (ADDRESS_FLAG))
        {
            nqprintf("DIAG Read Word (address: 0x%x)\n", address);
            ReadTargetWord(dev, address, &param);

            if (quiet()) {
                printf("0x%x\n", param);
            } else {
                printf("Value in target at 0x%x: 0x%x (%d)\n",
                        address, param, param);
            }
        }
        else usage();
        break;

    case DIAG_WRITE_WORD:
        if ((flag & (ADDRESS_FLAG | PARAM_FLAG)) == (ADDRESS_FLAG | PARAM_FLAG))
        {
            A_UINT32 origvalue = 0;

            if (flag & BITWISE_OP_FLAG) {
                /* first read */
                ReadTargetWord(dev, address, &origvalue);
                param = origvalue;

                /* now modify */
                if (flag & AND_OP_FLAG) {
                    param &= bitwise_mask;
                } else {
                    param |= bitwise_mask;
                }
            /* fall through to write out the parameter */
            }

            if (flag & BITWISE_OP_FLAG) {
                if (quiet()) {
                    printf("0x%x\n", origvalue);
                } else {
                    printf("DIAG Bit-Wise (%s) modify Word (address: 0x%x,"
                           " orig:0x%x, new: 0x%x,  mask:0x%X)\n",
                           (flag & AND_OP_FLAG) ? "AND" : "OR", address,
                           origvalue, param, bitwise_mask );
                }
            } else{
                nqprintf("DIAG Write Word (address: 0x%x, param:"
                         " 0x%x)\n", address, param);
            }
            WriteTargetWord(dev, address, param);
        }
        else usage();
        break;

    default:
        usage();
    }

    exit (0);
}
