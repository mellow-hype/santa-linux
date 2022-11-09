#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/netlink.h>
#include <linux/path.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>

// Maxlen for symbol targets for probing
#define MAX_SYMBOL_LEN 64
// Max netlink payload
#define MAX_PAYLOAD 1024
// Custom version for our protocol
#define NL_SANTA_CUSTOM_PROTO 30
// Module name
#define KMOD_NAME "santa-KMOD"
// Custom Netlink family name
#define FAMILY_NAME "gnl_santa"

/**
 * ================================================================================================
 * GLOBALS
 * ================================================================================================
 *
 * Agent PID (port id) of the daemon in userspace. The kmod will save this value once it
 * receives a checkin command from the daemon.
 */
static int agent_pid = -1;
/* Completion object used to hold execs while the daemon sends back a response */
static DECLARE_COMPLETION(hash_done);


/**
 * ================================================================================================
 * NETLINK SETUP
 * ================================================================================================
 *
 * ====================
 * GNL CALLBACK (PROTOTYPES)
 * ====================
 */
/* callback for handling msg command */
int gnl_cb_santa_msg_doit(struct sk_buff *sender_skb, struct genl_info *info);
/* callback for handling hash-done command */
int gnl_cb_santa_hash_done_doit(struct sk_buff *sender_skb, struct genl_info *info);
/* callback for handling check-in message */
int gnl_cb_santa_checkin_doit(struct sk_buff *sender_skb, struct genl_info *info);
/* error reply callback */
int gnl_cb_doit_reply_error(struct sk_buff *sender_skb, struct genl_info *info);
/* callback for handling pid command */
int gnl_cb_santactl_get_pid_doit(struct sk_buff *sender_skb, struct genl_info *info);

/*
 * ====================
 * PROTOCOL ATTRIBUTES
 * ====================
 * These are the attributes that we want to share in netlink family.
 * You can understand an attribute as a semantic type. This is the payload of Netlink messages.
 * GNl: Generic Netlink
 */
enum GNL_SANTA_ATTRIBUTE {
    /* 0 is never used (=> UNSPEC) */
    GNL_SANTA_A_UNSPEC,
    /* We expect a MSG to be a null-terminated C-string. */
    GNL_SANTA_A_MSG,
    /* Unused marker field to get the length/count of enum entries. No real attribute. */
    __GNL_SANTA_A_MAX,
};
/*ffffber of elements in `enum GNL_SANTA_ATTRIBUTE`. */
#define GNL_SANTA_ATTRIBUTE_ENUM_LEN (__GNL_SANTA_A_MAX)
/* The number of actual usable attributes in `enum GNL_SANTA_ATTRIBUTE`. (-1 because UNSPEC) */
#define GNL_SANTA_ATTRIBUTE_COUNT (GNL_SANTA_ATTRIBUTE_ENUM_LEN - 1)

/**
 * ====================
 * PROTOCOL COMMANDS
 * ====================
 * Enumeration of all commands (functions) that our custom protocol on top
 * of generic netlink supports. This can be understood as the action that
 * we want to trigger on the receiving side.
 */
typedef enum GNL_SANTA_COMMAND {
    /* 0 is never used (=> UNSPEC) first real command is "1" (>0) */
    GNL_SANTA_C_UNSPEC,
    /**
     * When this command is received, we expect the attribute `GNL_SANTA_ATTRIBUTE::GNL_SANTA_A_MSG` to
     * be present in the Generic Netlink request message.
     */
    GNL_SANTA_C_MSG,
    // CHECK-IN command
    GNL_SANTA_C_MSG_CHECKIN,
    // GETPID command
    GNL_SANTA_C_MSG_PID,
    // HASH DONE command
    GNL_SANTA_C_MSG_HASH_DONE,
    // Reply with error
    GNL_SANTA_C_REPLY_WITH_NLMSG_ERR,
    /* Unused marker field to get the length/count of enum entries. No real attribute. */
    __GNL_SANTA_C_MAX,
} SantaCommand_t;

/* Number of elements in `enum GNL_SANTA_COMMAND`. */
#define GNL_SANTA_COMMAND_ENUM_LEN (__GNL_SANTA_C_MAX)
/* The number of actual usable commands  in `enum GNL_SANTA_COMMAND`. */
#define GNL_SANTA_COMMAND_COUNT (GNL_SANTA_COMMAND_ENUM_LEN - 1)

/* The length of the genl_ops struct for gnl_santa_ops. */
#define GNL_SANTA_OPS_LEN (GNL_SANTA_COMMAND_COUNT)

/**
 * ====================
 * GNL OPERATIONS
 * ====================
 * An array with all operations that will be supported by our custom protocol
 */
struct genl_ops gnl_santa_ops[GNL_SANTA_OPS_LEN] = {
    // MSG
    {
        .cmd = GNL_SANTA_C_MSG,
        .flags = 0,
        .internal_flags = 0,
        /* Callback handler when a request with the specified ".cmd" above is received.
         * Always validates the payload except one set NO_STRICT_VALIDATION flag in ".validate"
         * See: https://elixir.bootlin.com/linux/v5.11/source/net/netlink/genetlink.c#L717
         *
         * Quote from: https://lwn.net/Articles/208755
         *  "The 'doit' handler should do whatever processing is necessary and return
         *   zero on success, or a negative value on failure.  Negative return values
         *   will cause a NLMSG_ERROR message to be sent while a zero return value will
         *   only cause a NLMSG_ERROR message to be sent if the request is received with
         *   the NLM_F_ACK flag set."
         *
         * You can find this in Linux code here:
         * https://elixir.bootlin.com/linux/v5.11/source/net/netlink/af_netlink.c#L2499
         */
        .doit = gnl_cb_santa_msg_doit, // handler
        .dumpit = NULL,
        .start = NULL,
        .done = NULL,
        .validate = 0,
    },
    // MSG_CHECKIN
    {
        .cmd = GNL_SANTA_C_MSG_CHECKIN,
        .flags = 0,
        .internal_flags = 0,
        .doit = gnl_cb_santa_checkin_doit, // handler
        .dumpit = NULL,
        .start = NULL,
        .done = NULL,
        .validate = 0,
    },
    // MSG_PID
    {
        .cmd = GNL_SANTA_C_MSG_PID,
        .flags = 0,
        .internal_flags = 0,
        .doit = gnl_cb_santactl_get_pid_doit, // handler
        .dumpit = NULL,
        .start = NULL,
        .done = NULL,
        .validate = 0,
    },
    // MSG_HASH_DONE
    {
        .cmd = GNL_SANTA_C_MSG_HASH_DONE,
        .flags = 0,
        .internal_flags = 0,
        .doit = gnl_cb_santa_hash_done_doit, // handler
        .dumpit = NULL,
        .start = NULL,
        .done = NULL,
        .validate = 0,
    },
    // MSG_REPLY_ERROR
    {
        .cmd = GNL_SANTA_C_REPLY_WITH_NLMSG_ERR,
        .flags = 0,
        .internal_flags = 0,
        .doit = gnl_cb_doit_reply_error, // handler
        .dumpit = NULL,
        .start = NULL,
        .done = NULL,
        .validate = 0,
    }
};

/**
 * ====================
 * GNL POLICY
 * ====================
 * Attribute policy: defines which attribute has which type (e.g int, char * etc).
 * This get validated for each received Generic Netlink message, if not deactivated
 * in `gnl_santa_ops[].validate`.
 * See https://elixir.bootlin.com/linux/v5.11/source/net/netlink/genetlink.c#L717
 */
static struct nla_policy gnl_santa_policy[GNL_SANTA_ATTRIBUTE_ENUM_LEN] = {
    [GNL_SANTA_A_UNSPEC] = {.type = NLA_UNSPEC},
    [GNL_SANTA_A_MSG] = {.type = NLA_NUL_STRING} // MSG expects a null-terminated C string
};

/**
 * ====================
 * GNL FAMILY
 * ====================
 * Definition of the custom netlink protocol family we'll be registering.
*/
static struct genl_family gnl_santa_family = {
    // have the kernel auto assign the id
    .id = 0,
   // we don't use custom additional header info / user specific header
    .hdrsize = 0,
    // The name of this family, used by userspace application to get the numeric ID
    .name = FAMILY_NAME,
    // family specific version number; can be used to evolve application over time (multiple versions)
    .version = NL_SANTA_CUSTOM_PROTO,
    // delegates all incoming requests to callback functions
    .ops = gnl_santa_ops,
    // length of array `gnl_santa_ops`
    .n_ops = GNL_SANTA_OPS_LEN,
    // attribute policy (for validation of messages). Enforced automatically, except ".validate" in
    // corresponding ".ops"-field is set accordingly.
    .policy = gnl_santa_policy,
    // Number of attributes / bounds check for policy (array length)
    .maxattr = GNL_SANTA_ATTRIBUTE_ENUM_LEN,
    // Owning Kernel module of the Netlink family we register.
    .module = THIS_MODULE,
    // if your application must handle multiple netlink calls in parallel (where one should not block the next
    // from starting), set this to true! otherwise all netlink calls are mutually exclusive
    .parallel_ops = 0,
    // set to true if the family can handle network namespaces and should be presented in all of them
    .netnsok = 0,
    // called before an operation's doit callback
    .pre_doit = NULL,
    // called after an operation's doit callback
    .post_doit = NULL,
};

/**
 * ====================
 * GNL MSG CALLBACK HANDLER IMPLEMENTATION
 * ====================
*/
int gnl_cb_santa_msg_doit(struct sk_buff *sender_skb, struct genl_info *info) {
    char *recv_msg;
    struct nlattr *na;

    // check we got info in a good state
    if (info == NULL) {
        pr_err("An error occurred in %s():\n", __func__);
        return -EINVAL;
    }

    // We'll only accept messages from the pid from the daemon that checked in
    if (agent_pid > 0 && info->snd_portid != agent_pid) {
        pr_err("[%s]: message doesn't appear to be from the daemon, ignoring\n", KMOD_NAME);
        return 0;
    }

    // Get the attribute at the index indicated by the respective attribute enum (e.g. GNL_SANTA_A_MSG)
    na = info->attrs[GNL_SANTA_A_MSG];
    if (!na) {
        pr_err("no info->attrs[%i]\n", GNL_SANTA_A_MSG);
        return -EINVAL; // we return here because we expect to recv a msg
    }

    // Read the data portion of the nlattr
    recv_msg = (char *) nla_data(na);
    if (recv_msg == NULL) {
        pr_err("error while receiving data\n");
    } else {
        pr_info("received: '%s'\n", recv_msg);
    }
    return 0;
}

/**
 * ====================
 * GNL GETPID CALLBACK HANDLER IMPLEMENTATION
 * ====================
*/
int gnl_cb_santactl_get_pid_doit(struct sk_buff *sender_skb, struct genl_info *info) {
    struct sk_buff *reply_skb;
    int rc;
    void *msg_head;
    char resp_msg[MAX_PAYLOAD];

    // check we got info in a good state
    if (info == NULL) {
        // should never happen
        pr_err("An error occurred in %s():\n", __func__);
        return -EINVAL;
    }

    /* Send a message back */
    reply_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (reply_skb == NULL) {
        pr_err("An error occurred in %s():\n", __func__);
        return -ENOMEM;
    }

    // Create the message headers
    msg_head = genlmsg_put(
            reply_skb,          // buffer for netlink message: struct sk_buff *
            info->snd_portid,   // sending port (not process) id: int
            0,                  // sequence number: int (might be used by receiver, but not mandatory)
            &gnl_santa_family,  // struct genl_family *
            0,                  // flags for Netlink header: int; application specific and not mandatory
            GNL_SANTA_C_MSG     // The command/operation (u8) from `enum GNL_SANTA_COMMAND`
    );
    if (msg_head == NULL) {
        rc = ENOMEM;
        pr_err("An error occurred in %s():\n", __func__);
        return -rc;
    }

    // Plave the PID in the GNL_SANTA_A_MSG attribute
    snprintf(resp_msg, sizeof(resp_msg), "%d", agent_pid);
    rc = nla_put_string(reply_skb, GNL_SANTA_A_MSG, resp_msg);
    if (rc != 0) {
        pr_err("An error occurred in %s():\n", __func__);
        return -rc;
    }

    // Finalize the message
    genlmsg_end(reply_skb, msg_head);

    // Send the response
    rc = genlmsg_reply(reply_skb, info);
    if (rc != 0) {
        pr_err("An error occurred in %s():\n", __func__);
        return -rc;
    }
    return 0;
}


/**
 * ====================
 * GNL MSG_CHECKIN CALLBACK HANDLER IMPLEMENTATION
 * ====================
*/
int gnl_cb_santa_checkin_doit(struct sk_buff *sender_skb, struct genl_info *info) {
    struct sk_buff *reply_skb;
    int rc;
    void *msg_head;
    char resp_msg[MAX_PAYLOAD];

    // check we got info in a good state
    if (info == NULL) {
        // should never happen
        pr_err("An error occurred in %s():\n", __func__);
        return -EINVAL;
    }

    // only accept messages from the daemon
    if (agent_pid > 0 && info->snd_portid != agent_pid) {
        pr_err("[%s]: message doesn't appear to be from the daemon, ignoring\n", KMOD_NAME);
        return 0;
    }

    // ensure it's the first checkin
    if (agent_pid < 0) {
        // update the agent_pid global if it is the first check-in
        agent_pid = info->snd_portid;
        strcpy(resp_msg, "CHECKIN-OK");
    } else {
        pr_err("[%s]: ignoring bad check-in; the daemon has already checked-in", KMOD_NAME);
        return 0;
    }

    /* Send a message back */
    // Allocate some memory, since the size is not yet known use NLMSG_GOODSIZE
    reply_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (reply_skb == NULL) {
        pr_err("An error occurred in %s():\n", __func__);
        return -ENOMEM;
    }

    // Create the message headers
    msg_head = genlmsg_put(
            reply_skb,          // buffer for netlink message: struct sk_buff *
            info->snd_portid,   // sending port (not process) id: int
            0,                  // sequence number: int (might be used by receiver, but not mandatory)
            &gnl_santa_family,  // struct genl_family *
            0,                  // flags for Netlink header: int; application specific and not mandatory
            GNL_SANTA_C_MSG     // The command/operation (u8) from `enum GNL_SANTA_COMMAND`
    );
    if (msg_head == NULL) {
        rc = ENOMEM;
        pr_err("An error occurred in %s():\n", __func__);
        return -rc;
    }

    // Add a GNL_SANTA_A_MSG attribute (actual value/payload to be sent)
    rc = nla_put_string(reply_skb, GNL_SANTA_A_MSG, resp_msg);
    if (rc != 0) {
        pr_err("An error occurred in %s():\n", __func__);
        return -rc;
    }

    /* Finalize the message:
     * Corrects the netlink message header (length) to include the appended
     * attributes. Only necessary if attributes have been added to the message.
     */
    genlmsg_end(reply_skb, msg_head);

    // Send the response
    rc = genlmsg_reply(reply_skb, info);
    if (rc != 0) {
        pr_err("An error occurred in %s():\n", __func__);
        return -rc;
    }
    return 0;
}

/**
 * ====================
 * GNL MSG_HASH_DONE CALLBACK HANDLER IMPLEMENTATION
 * ====================
*/
int gnl_cb_santa_hash_done_doit(struct sk_buff *sender_skb, struct genl_info *info) {
    // check we got info in a good state
    if (info == NULL) {
        // should never happen
        pr_err("An error occurred in %s():\n", __func__);
        return -EINVAL;
    }
    // only accept messages from the daemon
    if (agent_pid > 0 && info->snd_portid != agent_pid) {
        pr_err("[%s]: message doesn't appear to be from the daemon, ignoring\n", KMOD_NAME);
        return 0;
    }
    // Trigger the completion to let the kprobe resume
    complete(&hash_done);
    return 0;
}

// placeholder for example error reply handler
int gnl_cb_doit_reply_error(struct sk_buff *sender_skb, struct genl_info *info) {
    return -EINVAL;
}


/**
 * ====================
 * CUSTOM GNL SANTA send_cmd()
 * ====================
*/
static int gnl_santa_send_cmd(SantaCommand_t cmd, char *msg) {
    struct sk_buff *reply_skb;
    void *msg_head;
    int rc;

    // check if we know the agent PID yet, bail if not
    if (agent_pid < 0) {
        printk(KERN_ERR "agent has not checked in yet, don't know the PID. is it running?\n");
        return -1;
    }

    // Allocate some memory, since the size is not yet known use NLMSG_GOODSIZE
    reply_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (reply_skb == NULL) {
        pr_err("An error occurred in %s():\n", __func__);
        return -ENOMEM;
    }

    // Create the message headers
    msg_head = genlmsg_put(
            reply_skb, // buffer for netlink message: struct sk_buff *
            agent_pid, // sending port (not process) id: int
            0, // sequence number: int (might be used by receiver, but not mandatory)
            &gnl_santa_family, // struct genl_family *
            0, // flags for Netlink header: int; application specific and not mandatory
            cmd // the command/op from the GNL_SANTA_COMMAND enum
    );
    if (msg_head == NULL) {
        rc = ENOMEM;
        pr_err("An error occurred in %s(): after genlmsg_put\n", __func__);
        return -rc;
    }

    // Add a GNL_SANTA_A_MSG attribute (actual value/payload to be sent)
    rc = nla_put_string(reply_skb, GNL_SANTA_A_MSG, msg);
    if (rc != 0) {
        pr_err("An error occurred in %s(): after nla_put_string\n", __func__);
        return -rc;
    }

    // Finalize the message:
    genlmsg_end(reply_skb, msg_head);

    // Send the message back
    // see https://elixir.bootlin.com/linux/v5.8.9/source/include/net/genetlink.h#L326
    rc = genlmsg_unicast(&init_net, reply_skb, agent_pid);
    if (rc != 0) {
        pr_err("An error occurred in %s(): after genlmsg_unicast\n", __func__);
        return -rc;
    }
    return 0;
}


/**
 * ================================================================================================
 * KPROBE SETUP
 * ================================================================================================
 * The kprobe infrastructure is used to intercept calls to finalize_exec(), which
 * effectively allows us to intercept execve calls at the last part, once the exe
 * data has been read into memory and the exe/fs data structures flushed and updated.
 */
/* Symbol that will be probed and module param setup */
static char symbol[MAX_SYMBOL_LEN] = "finalize_exec";
module_param_string(symbol, symbol, sizeof(symbol), 0644);
static struct kprobe kpr = { .symbol_name = symbol,};

/**
 * ========================
 * KPROBE PRE_HANDLER: finalize_exec()
 * ========================
 * Pre-handler for finalize_exec()
 */
static int handler_pre_finalize_exec(struct kprobe *p, struct pt_regs *regs)
{
    char msg[MAX_PAYLOAD+4+1];
    memset(msg, 0, sizeof(msg));
    snprintf(msg, sizeof(msg), "%d", current->pid);

    // send the message to the daemon
    SantaCommand_t cmd = GNL_SANTA_C_MSG;
    int res = gnl_santa_send_cmd(cmd, msg);
    if (res != 0) {
        pr_err("[%s]: ERROR %s() ret=%d\n", KMOD_NAME, __func__, res);
        return 0;
    }
    // hold until we get a response from the daemon?
    wait_for_completion(&hash_done);
    return 0;
}


/**
 * ========================
 * KPROBE FAULT HANDLER
 * ========================
 * Pre-handler for finalize_exec()
 */
// fault handler
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    pr_info("[%s kprobe_FAULT] fault_handler: p->addr = 0x%px, trap #%dn",
        symbol, p->addr, trapnr);
    /* Return 0 because we don't handle the fault. */
    return 0;
}


// KERNEL MODULE INIT
static int __init hyperprobe_init(void)
{
    // SET UP FOR PROBE
    // set the pre, post, and fault handlers (use NULL for optional ones)
    kpr.pre_handler = handler_pre_finalize_exec;
    kpr.post_handler = NULL;
    kpr.fault_handler = handler_fault;

    int ret = register_kprobe(&kpr);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    pr_info("Inserted kprobe at %px for symbol %s\n", kpr.addr, symbol);

    // SET UP FOR NETLINK
    pr_info("Initializing the netlink protocol for the module\n");

    // register the family with its ops and policies
    int rc = genl_register_family(&gnl_santa_family);
    if (rc != 0) {
        pr_err("Error creating netlink socket\n");
        return -10;
    }
    pr_info("santa-KMOD init succeeded!\n");
    return 0;
}

// KERNEL MODULE EXIT
static void __exit hyperprobe_exit(void)
{
    unregister_kprobe(&kpr);
    pr_info("kprobe at %px for symbol %s unregistered\n", kpr.addr, symbol);
    int ret = genl_unregister_family(&gnl_santa_family);
    if (ret != 0) {
        pr_err("failed to unregister netlink proto: %i\n", ret);
        return;
    }
    pr_info("santa-KMOD netlink socket released\n");
}

module_init(hyperprobe_init)
module_exit(hyperprobe_exit)
MODULE_LICENSE("GPL");
