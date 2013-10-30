/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <limits.h>
#include <asm/types.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <sys/socket.h>
#include <linux/netlink.h>

#include <athdefs.h>
#include <a_types.h>
#include "dbglog.h"
#include "dbglog_host.h"


#define LOGFILE_FLAG           0x01
#define CONSOLE_FLAG           0x02
#define QXDM_FLAG              0x04

const char options[] =
"Options:\n\
-f, --logfile=<Output log file> [Mandotory]\n\
-r, --reclimit=<Maximum number of records before the log rolls over> [Optional]\n\
-c, --console (prints the logs in the console)\n\
-q, --qxdm  (prints the logs in the qxdm)\n\
The options can also be given in the abbreviated form --option=x or -o x. The options can be given in any order";

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

static FILE *fwlog_res;
static FILE *log_out;
const char *fwlog_res_file;
int max_records;
int record;
const char *progname;
char dbglogoutfile[PATH_MAX];
int optionflag;

int rec_limit = 1000000; /* Million records is a good default */

static void
usage(void)
{
    fprintf(stderr, "Usage:\n%s options\n", progname);
    fprintf(stderr, "%s\n", options);
    exit(-1);
}

extern int parser_init();


extern int
dbglog_parse_debug_logs(u_int8_t *datap, u_int16_t len);

static unsigned int get_le32(const unsigned char *pos)
{
    return pos[0] | (pos[1] << 8) | (pos[2] << 16) | (pos[3] << 24);
}

static size_t reorder(FILE *log_in, FILE *log_out)
{
    unsigned char buf[RECLEN];
    size_t res;
    unsigned int timestamp, min_timestamp = -1;
    int pos = 0, min_pos = 0;

    pos = 0;
    while ((res = fread(buf, RECLEN, 1, log_in)) == 1) {
        timestamp = get_le32(buf);
        if (timestamp < min_timestamp) {
                min_timestamp = timestamp;
                min_pos = pos;
        }
        pos++;
    }
    printf("First record at position %d\n", min_pos);

    fseek(log_in, min_pos * RECLEN, SEEK_SET);
    while ((res = fread(buf, RECLEN, 1, log_in)) == 1) {
        printf("Read record timestamp=%u length=%u\n",
               get_le32(buf), get_le32(&buf[4]));
        if (fwrite(buf, RECLEN, res, log_out) != res)
               perror("fwrite");
    }

    fseek(log_in, 0, SEEK_SET);
    pos = min_pos;
    while (pos > 0 && (res = fread(buf, RECLEN, 1, log_out)) == 1) {
        pos--;
        printf("Read record timestamp=%u length=%u\n",
                get_le32(buf), get_le32(&buf[4]));
        if (fwrite(buf, RECLEN, res, log_out) != res)
                perror("fwrite");
    }

    return 0;
}

static void cleanup(void) {
    close(sock_fd);

    fwlog_res = fopen(fwlog_res_file, "w");

    if (fwlog_res == NULL) {
        perror("Failed to open reorder fwlog file");
        goto out;
    }

    reorder(log_out, fwlog_res);
out:
    fclose(fwlog_res);
    fclose(log_out);
}

static void stop(int signum)
{

    if(optionflag & LOGFILE_FLAG){
        printf("Recording stopped\n");
        cleanup();
    }
    exit(0);
}

int main(int argc, char *argv[])
{
    int res =0;
    unsigned char *buf;
    int c;
    char *mesg="Hello";

    progname = argv[0];

    int option_index = 0;
    static struct option long_options[] = {
        {"logfile", 1, NULL, 'f'},
        {"reclimit", 1, NULL, 'r'},
        {"console", 0, NULL, 'c'},
        {"qxdm", 0, NULL, 'q'},
        { 0, 0, 0, 0}
    };

    while (1) {
        c = getopt_long (argc, argv, "f:cq:r:", long_options, &option_index);
        if (c == -1) break;

        switch (c) {
            case 'f':
                memset(dbglogoutfile, 0, PATH_MAX);
                memcpy(dbglogoutfile, optarg, strlen(optarg));
                optionflag |= LOGFILE_FLAG;
                break;

            case 'c':
                optionflag |= CONSOLE_FLAG;
                break;

            case 'q':
                printf("Do it for QXDM \n");
                optionflag |= QXDM_FLAG;
                break;

            case 'r':
                rec_limit = strtoul(optarg, NULL, 0);
                break;

            default:
                usage();
        }
    }

    if (!(optionflag & (LOGFILE_FLAG | CONSOLE_FLAG | QXDM_FLAG))) {
        usage();
	return -1;
    }

    sock_fd = socket(PF_NETLINK, SOCK_RAW, CLD_NETLINK_USER);
    if (sock_fd < 0)
        return -1;

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* self pid */

    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(RECLEN));
    memset(nlh, 0, NLMSG_SPACE(RECLEN));
    nlh->nlmsg_len = NLMSG_SPACE(RECLEN);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    memcpy(NLMSG_DATA(nlh), mesg, strlen(mesg));

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sendmsg(sock_fd, &msg, 0);

    signal(SIGINT, stop);
    signal(SIGTERM, stop);

    if (optionflag & LOGFILE_FLAG) {

        if (rec_limit < RECLEN) {
            fprintf(stderr, "Too small maximum length (has to be >= %d)\n",
                    RECLEN);
            close(sock_fd);
            return -1;
        }
        max_records = rec_limit / RECLEN;
        printf("Storing last %d records\n", max_records);

        log_out = fopen(dbglogoutfile, "w");
        if (log_out == NULL) {
            perror("Failed to create output file");
            close(sock_fd);
            return -1;
        }

        fwlog_res_file = "./reorder";

        /* Read message from kernel */
        while ((res = recvmsg(sock_fd, &msg, 0)) > 0)  {
            buf = (unsigned char *)NLMSG_DATA(nlh);
            printf("Read record timestamp=%u length=%u \n",
                   get_le32(&buf[0]), get_le32(&buf[4]));
            fseek(log_out, record * RECLEN, SEEK_SET);
            if ((res = fwrite(buf, RECLEN, 1, log_out)) != 1){
                    perror("fwrite");
		    break;
	    }
             record++;
            if (record == max_records)
                    record = 0;
        }

    printf("Incomplete read: %d bytes\n", (int) res);
    cleanup();
    }

    if (optionflag & CONSOLE_FLAG) {

        parser_init();

        while ((res = recvmsg(sock_fd, &msg, 0)) > 0)  {
            buf = (unsigned char *)NLMSG_DATA(nlh);
            dbglog_parse_debug_logs(&buf[8], get_le32(&buf[4]));
        }
        close(sock_fd);
    }

    return 0;
}
