#ifndef _NETLINK_HELPER_H
#define _NETLINK_HELPER_H

#include "dependency.h"

// ---- APP 与 Kernel 通用协议 ------
#define MAXRuleNameLen 11

#define REQ_GETAllIPRules 1
#define REQ_ADDIPRule 2
#define REQ_DELIPRule 3
#define REQ_SETAction 4 
#define REQ_GETAllIPLogs 5
#define REQ_GETAllConns 6
#define REQ_ADDNATRule 7
#define REQ_DELNATRule 8
#define REQ_GETNATRules 9

#define RSP_Only_Head 10
#define RSP_MSG 11
#define RSP_IPRules 12
#define RSP_IPLogs 13
#define RSP_NATRules 14

struct IPRule {
    char name[MAXRuleNameLen+1];
    unsigned int saddr;
    unsigned int smask;
    unsigned int daddr;
    unsigned int dmask;
    unsigned int sport; // 源端口范围 高2字节为最小 低2字节为最大
    unsigned int dport; // 目的端口范围 同上
    u_int8_t protocol;
    unsigned int action;
    unsigned int log;
    struct IPRule* nx;
};

struct IPLog {
    long tm;
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    u_int8_t protocol;
    unsigned int len;
    unsigned int action;
    struct IPLog* nx;
};

struct NATRecord { // NAT 记录or规则 （源端口转换）
    unsigned int saddr;
    unsigned int smask; // 仅当作为一条NAT规则时起作用
    unsigned int daddr;

    unsigned short sport; // 当作为一条NAT规则时，代表最小端口范围
    unsigned short dport; // 当作为一条NAT规则时，代表最大端口范围
    struct NATRecord* nx;
};

struct APPRequest {
    unsigned int tp;
    char ruleName[MAXRuleNameLen+1];
    union {
        struct IPRule ipRule;
        unsigned int defaultAction;
        unsigned int num;
    } msg;
};

struct KernelResponseHeader {
    unsigned int bodyTp;
    unsigned int arrayLen;
};

// ----- netlink 相关 -----
#include <linux/netlink.h>

// netlink 协议号
#define NETLINK_MYFW 17

struct sock *netlink_init(void);
void netlink_release(void);
int nlSend(unsigned int pid, void *data, unsigned int len);

// ----- 应用交互相关 -------
int dealAppMessage(unsigned int pid, void *msg, unsigned int len);
void* formAllIPRules(unsigned int *len);
struct IPRule * addIPRuleToChain(char after[], struct IPRule rule);
int delIPRuleFromChain(char name[]);
void* formAllIPLogs(unsigned int num, unsigned int *len);
void* formAllConns(unsigned int *len);
struct NATRecord * addNATRuleToChain(struct NATRecord rule);
int delNATRuleFromChain(int num);
void* formAllNATRules(unsigned int *len);

// ----- netfilter相关 -----
// 最大缓存日志长度
#define MAX_LOG_LEN 1000

struct IPRule matchIPRules(struct sk_buff *skb, int *isMatch);
int addLog(struct IPLog log);
int addLogBySKB(unsigned int action, struct sk_buff *skb);

// ----- 连接池相关 --------
#include <linux/rbtree.h>

#define CONN_NEEDLOG 0x10
#define CONN_MAX_SYM_NUM 3
// 新建连接或已有连接刷新时的存活时长（秒）
#define CONN_EXPIRES 7
// 定期清理超时连接的时间间隔（秒）
#define CONN_ROLL_INTERVAL 5

#define NAT_TYPE_NO 0
#define NAT_TYPE_SRC 1
#define NAT_TYPE_DEST 2

typedef unsigned int conn_key_t[CONN_MAX_SYM_NUM]; // 连接标识符，用于标明一个连接，可比较

typedef struct connNode {
    struct rb_node node;
    conn_key_t key; // 连接标识符
    unsigned long expires; // 超时时间
    u_int8_t protocol; // 协议，仅用于向用户展示
    u_int8_t needLog; // 是否记录日志，仅用于hook

    struct NATRecord nat;  // 该连接对应的NAT记录
    int natType;           // NAT 转换类型
}connNode;

#define timeFromNow(plus) (jiffies + ((plus) * HZ))

void conn_init(void);
void conn_exit(void);
struct connNode *hasConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport);
struct connNode *addConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport, u_int8_t proto, u_int8_t log);
bool matchOneRule(struct IPRule *rule, unsigned int sip, unsigned int dip, unsigned short sport, unsigned int dport, u_int8_t proto);
int eraseConnRelated(struct IPRule rule);

// ---- NAT 初始操作相关 ----

int setConnNAT(struct connNode *node, struct NATRecord record, int natType);
struct NATRecord *matchNATRule(unsigned int sip);

#endif