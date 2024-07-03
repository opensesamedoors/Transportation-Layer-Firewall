#include "tools.h"
#include "helper.h"
#include "hook.h"

unsigned int DEFAULT_ACTION = NF_ACCEPT;

unsigned int hook_main(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) {
    struct IPRule rule;
    struct connNode *conn;
    unsigned short sport, dport;
    unsigned int sip, dip, action = DEFAULT_ACTION;
    int isMatch = 0, isLog = 0;
    
    struct iphdr *header = ip_hdr(skb);
    getPort(skb,header,&sport,&dport);
    sip = ntohl(header->saddr);
    dip = ntohl(header->daddr);

    conn = hasConn(sip, dip, sport, dport);
    if(conn != NULL) {
        if(conn->needLog)
            addLogBySKB(action, skb);
        return NF_ACCEPT;
    }
    
    // match rules
    rule = matchIPRules(skb, &isMatch);
    if(isMatch) {
        printk(KERN_DEBUG "[fw netfilter] patch rule %s.\n", rule.name);
        action = (rule.action == NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
        if(rule.log) {
            isLog = 1;
            addLogBySKB(action, skb);
        }
    }
    
    if(action == NF_ACCEPT) {
        addConn(sip,dip,sport,dport,header->protocol,isLog);
    }
    return action;
}
