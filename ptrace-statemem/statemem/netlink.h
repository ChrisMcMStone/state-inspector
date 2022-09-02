#ifndef PTRACE_NETLINK_H_
#define PTRACE_NETLINK_H_

#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>

// libnl
#include <linux/netlink.h>
#include <netlink/genl/genl.h>
#include <linux/nl80211.h>

typedef enum Frame {
    Frame_None,
    Frame_Unknown,
    Frame_Auth,
    Frame_Deauth,
    Frame_AssocReq,
    Frame_AssocResp,
    Frame_Disassoc,
    Frame_Eapol,
    Frame_Unexpected,
    Frame_Error
} Frame;

int init_nl80211_id();

Frame process_netlink_msg(struct nlmsghdr *nlh);
Frame monitor_recvmsg(trace_t *t);
Frame monitor_sendmsg(trace_t *t);

const char * frame2str(Frame frame);

#endif // PTRACE_NETLINK_H_
