#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

// ptrace-burrito
#include "breakpoints.h"
#include "debug.h"
#include "debug_syscalls.h"
#include "errors.h"
#include "process.h"
#include "symbols.h"
#include "trace.h"
#include "util.h"

#include "statemem.h"
#include "netlink.h"

static int netlink_nl80211_id = 0;

//#define DEBUG_NETLINK

const char * frame2str(Frame frame)
{
    switch (frame)
    {
    case Frame_Unknown:
        return "Unknown";
    case Frame_Auth:
        return "Auth";
    case Frame_Deauth:
        return "Deauth";
    case Frame_AssocReq:
        return "AssocReq";
    case Frame_AssocResp:
        return "AssocResp";
    case Frame_Disassoc:
        return "Disassoc";
    case Frame_Eapol:
        return "EAPOL";
    case Frame_None:
        return "None";
    case Frame_Unexpected:
        return "Unexpected";
    case Frame_Error:
        return "Error";
    default:
        return "UNKNOWN";
    }
}

int init_nl80211_id()
{
    struct nl_sock* socket;

    socket = nl_socket_alloc();
    if (!socket) { 
        fprintf(stderr, "Failed to allocate netlink socket.\n");
        return -1;
    }  

    if (genl_connect(socket)) { 
        fprintf(stderr, "Failed to connect to netlink socket.\n"); 
        nl_close(socket);
        nl_socket_free(socket);
        return -1;
    }

    netlink_nl80211_id = genl_ctrl_resolve(socket, "nl80211");
    if (netlink_nl80211_id < 0) {
        fprintf(stderr, "nl80211 interface not found.\n");
        nl_close(socket);
        nl_socket_free(socket);
        return -1;
    }

    nl_close(socket);
    nl_socket_free(socket);

    return 0;
}

static Frame inspect_netlink_msg(struct genlmsghdr *gnlh)
{
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

  switch (gnlh->cmd) {
  // These two are used by wpa_supplicant
  case NL80211_CMD_AUTHENTICATE:
#ifdef DEBUG_NETLINK
    fprintf(stderr, ">>> NL80211_CMD_AUTHENTICATE\n");
#endif
    return Frame_Auth;
  case NL80211_CMD_ASSOCIATE:
#ifdef DEBUG_NETLINK
    fprintf(stderr, ">>> NL80211_CMD_ASSOCIATE\n");
#endif
    return Frame_AssocReq;

  // This is used by hostapd, iwd to send authentication and association
  case NL80211_CMD_FRAME:
    if (tb[NL80211_ATTR_FRAME]) {
      unsigned char *buf = nla_data(tb[NL80211_ATTR_FRAME]);
      int type = (buf[0] >> 2) & 0x3;
      int subtype = (buf[0] >> 4) & 0xF;

#ifdef DEBUG_NETLINK
      int length = nla_len(tb[NL80211_ATTR_FRAME]);
      fprintf(stderr, ">>> NL80211_CMD_FRAME: type=%d subtype=%d length=%d\n",
             type, subtype, length);
#endif

      if (type == 0 && subtype == 0)
        return Frame_AssocReq;
      if (type == 0 && subtype == 1)
        return Frame_AssocResp;
      else if (type == 0 && subtype == 10)
        return Frame_Disassoc;
      else if (type == 0 && subtype == 11)
        return Frame_Auth;
      else if (type == 0 && subtype == 12)
        return Frame_Deauth;
      else if (type == 2)
        return Frame_Eapol;
      else
        return Frame_Unknown;
    }

  case NL80211_CMD_UNEXPECTED_FRAME:
#ifdef DEBUG_NETLINK
    // For us this event happens when the AP receives an EAPOL frame before being associated.
    // This event does not contain the frame itself (only the interface info and transmitter MAC address).
    fprintf(stderr, ">>> NL80211_CMD_UNEXPECTED_FRAME\n");
#endif
    return Frame_Unexpected;

  // NL80211_CMD_CONTROL_PORT_FRAME
  case 129:
    if (tb[NL80211_ATTR_FRAME]) {
#ifdef DEBUG_NETLINK
      unsigned char *buf = nla_data(tb[NL80211_ATTR_FRAME]);
      int length = nla_len(tb[NL80211_ATTR_FRAME]);

      fprintf(stderr, ">>> NL80211_CMD_CONTROL_PORT_FRAME: length=%d buf=%02X %02X ... %02X %02X\n",
             length, buf[0], buf[1], buf[length - 2], buf[length - 1]);
#endif
      return Frame_Eapol;
    }
    return Frame_None;

#ifdef DEBUG_NETLINK
  case NL80211_CMD_GET_KEY:
    fprintf(stderr, "NL80211_CMD_GET_KEY\n");
    break;
#endif

  // Used by both hostapd, wpa_supplicant, iwd (with various parameters)
  case NL80211_CMD_NEW_KEY:
    if (tb[NL80211_ATTR_KEY_DATA]) {
#ifdef DEBUG_NETLINK
      unsigned char *buf = nla_data(tb[NL80211_ATTR_KEY_DATA]);
      int length = nla_len(tb[NL80211_ATTR_KEY_DATA]);
      int key_idx = nla_get_u8(tb[NL80211_ATTR_KEY_IDX]);

      fprintf(stderr, ">>> NL80211_CMD_NEW_KEY: idx=%d key=%02X %02X ... %02X %02X\n",
             key_idx, buf[0], buf[1], buf[length - 2], buf[length - 1]);
#endif
    }
    return Frame_None;

#ifdef DEBUG_NETLINK
  case NL80211_CMD_NEW_STATION:
    fprintf(stderr, "NL80211_CMD_NEW_STATION\n");
    break;
  case NL80211_CMD_DEL_STATION:
    fprintf(stderr, "NL80211_CMD_DEL_STATION\n");
    break;
  case NL80211_CMD_DEL_KEY:
    fprintf(stderr, "NL80211_CMD_DEL_KEY\n");
    break;
  case NL80211_CMD_SET_STATION:
    fprintf(stderr, "NL80211_CMD_SET_STATION\n");
    break;
  case NL80211_CMD_FRAME_TX_STATUS:
    fprintf(stderr, "NL80211_CMD_FRAME_TX_STATUS\n");
    break;
#endif

  default:
#ifdef DEBUG_NETLINK
    fprintf(stderr, "Unknown gnlh->cmd=%d\n", gnlh->cmd);
#endif
    break;
  }

  return Frame_None;
}

Frame process_netlink_msg(struct nlmsghdr *nlh)
{
    // There might be multiple Netlink messages inside one syscall
    size_t len = nlh->nlmsg_len;
    for ( ; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len))
    {
#ifdef DEBUG_NETLINK
        fprintf(stderr, "nlh->nlmsg_type = %d (nl80211_id=%d)\n", nlh->nlmsg_type, netlink_nl80211_id);
#endif

        // Must be nl80211 message
        if (nlh->nlmsg_type == NLMSG_ERROR) {
#ifdef DEBUG_NETLINK
            struct nlmsgerr *err = NLMSG_DATA(nlh);
            fprintf(stderr, "nlh->error = %d\n", err->error);
#endif
            return Frame_Error;
        }
        if (nlh->nlmsg_type != netlink_nl80211_id)
            continue;

        // Return if a message was sent/received
        struct genlmsghdr *gnlh = nlmsg_data(nlh);
        Frame rval = inspect_netlink_msg(gnlh);
        if (rval > 0)
            return rval;
    }

    return Frame_None;
}

Frame monitor_recvmsg(trace_t *t)
{
    off_t msg_ex = get_syscall_arg(t, 1);
    int flags = get_syscall_arg(t, 2);
    struct msghdr msg;

    // Ignore PEEKs made by Hostapd
    if (flags & MSG_PEEK)
        return Frame_None;

    if (read_memory(t->pid, &msg, sizeof(msg), msg_ex) < 0)
        return Frame_None;

#if 0
    //
    // I don't think this is needed (was used in IWD code)
    //

    if (msg.msg_controllen <= 0)
        return 0;

    unsigned char *control = malloc(msg.msg_controllen);
    if (read_memory(t->pid, control, msg.msg_controllen, (off_t)msg.msg_control) < 0)
        return Frame_None;
    msg.msg_control = control;

    // Taken from ell/genl.c:received_data
    struct cmsghdr *cmsg;
    unsigned group = 0;
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
				    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
	    struct nl_pktinfo pktinfo;

	    if (cmsg->cmsg_level != SOL_NETLINK)
		    continue;

	    if (cmsg->cmsg_type != NETLINK_PKTINFO)
		    continue;

	    memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));

	    group = pktinfo.group;
    }

    if (group > 0) {
        free(msg.msg_control);
        return 0;
    }
#endif


    //
    // Process the actual message
    //

    struct iovec *msg_iov = malloc(sizeof(struct iovec));
    if (read_memory(t->pid, msg_iov, sizeof(struct iovec), (off_t)msg.msg_iov) < 0)
        return Frame_None;
    msg.msg_iov = msg_iov;

    struct nlmsghdr *nlh = malloc(msg_iov->iov_len);
    if (read_memory(t->pid, nlh, msg_iov->iov_len, (off_t)msg.msg_iov->iov_base) < 0)
        return Frame_None;
    msg.msg_iov->iov_base = nlh;

    Frame rval = process_netlink_msg(nlh);

    free(msg.msg_iov->iov_base);
    free(msg.msg_iov);

    return rval;
}


Frame monitor_sendmsg(trace_t *t)
{
    // ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
    off_t msg_ex = get_syscall_arg(t, 1);
    struct msghdr msg;
    read_memory(t->pid, &msg, sizeof(msg), msg_ex);

    struct iovec *msg_iov = malloc(sizeof(struct iovec));
    read_memory(t->pid, msg_iov, sizeof(struct iovec), (off_t)msg.msg_iov);
    msg.msg_iov = msg_iov;

    struct nlmsghdr *nlh = malloc(msg_iov->iov_len);
    read_memory(t->pid, nlh, msg_iov->iov_len, (off_t)msg.msg_iov->iov_base);
    msg.msg_iov->iov_base = nlh;

    Frame rval = process_netlink_msg(nlh);

    free(msg.msg_iov->iov_base);
    free(msg.msg_iov);

    return rval;
}

