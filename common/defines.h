#ifndef DEFINES_H
#define DEFINES_H

#define TRUE 1
#define FALSE 0

#define PATHSIZE 1024
#define SOCKETBUFSIZE 32 // entries in /proc/<pid>/fd are in the form of socket:[1234567]
#define NFQNUM_OUT 11220 //arbitrary number used for iptables rule
#define NFQNUM_OUTPUT_UDP 11222 //arbitrary number used for iptables rule
#define NFQNUM_OUTPUT_REST 11223 //arbitrary number used for iptables rule
#define NFQNUM_INPUT 11221
#define MAX_LINE_LENGTH 1024
#define DIGEST_SIZE 32
#define CTMARKOUT_BASE 11331 //conntrack marks start with this base number
//(to avoid possible collision with other programs that use conntrack marks
#define CTMARKIN_BASE  21331
#define CTMARK_DELTA 10000 //fixed number CTMARKIN_BASE - CTMARKOUT_BASE. N.B. use a number here, see below
#define MEMBUF_SIZE 65536 //buffer size to fread() /proc/net/tcp*,udp*

#define CT_ENTRIES_EXPORT_MAX 200
#define REFRESH_INTERVAL 1
#define TEST_FAILED SIGUSR1
#define TEST_SUCCEEDED SIGUSR2
#define MAGIC_NO 1111111111 //a token at the end of tcp_port_and_socket_cache
#define DIRECTION_IN 1
#define DIRECTION_OUT 2
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 5

#define PIDFILE "/tmp/lpfw.pid"
#define RULESFILE "/etc/lpfw.rules"
#define LPFW_LOGFILE "/tmp/lpfw.log"
#define TEST_LOGFILE "/tmp/lpfw.test_log"
#define TEST_TRAFFIC_LOG "/tmp/lpfw.test_traffic_log"
#define SAVE_IPTABLES_OUTPUT_FILE "/tmp/lpfw.output"
#define SAVE_IPTABLES_INPUT_FILE "/tmp/lpfw.input"

#define TCPINFO "/proc/net/tcp"
#define UDPINFO "/proc/net/udp"
#define TCP6INFO "/proc/net/tcp6"
#define UDP6INFO "/proc/net/udp6"
#define ICMPINFO "/proc/net/raw"

#define ALLOW_ONCE "ALLOW_ONCE"
#define ALLOW_ALWAYS "ALLOW_ALWAYS"
#define DENY_ONCE "DENY_ONCE"
#define DENY_ALWAYS "DENY_ALWAYS"
#define KERNEL_PROCESS "KERNEL_PROCESS"

#define MLOG_INFO 1
#define MLOG_TRAFFIC 2
#define MLOG_DEBUG 3
#define MLOG_DEBUG2 4
#define MLOG_ALERT 5
#define MLOG_ERROR 6
#define MLOG_DEBUG3 7

#endif // DEFINES_H
