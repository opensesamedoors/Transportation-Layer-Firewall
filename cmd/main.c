#include "contact.h"

struct KernelResponse cmdAddRule() {
    struct KernelResponse empty;
    char after[MAXRuleNameLen + 1],name[MAXRuleNameLen + 1],saddr[25],daddr[25],sport[15],dport[15],protoS[6];
    unsigned short sportMin,sportMax,dportMin,dportMax;
    unsigned int action = NF_DROP, log = 0, proto, i;
    empty.code = ERROR_CODE_EXIT;

    // rule position
    printf("add rule after [enter for adding at head]: ");
    for(i=0; ; i++) {
	if(i>MAXRuleNameLen) {
	    printf("name too long.\n");
	    return empty;
	}
	after[i] = getchar();
	if(after[i] == '\n' || after[i] == '\r') {
	    after[i] = '\0';
	    break;
	}
    }
    
    // rule name
    printf("rule name [max len=%d]: ", MAXRuleNameLen);
    scanf("%s",name);
    if(strlen(name)==0 || strlen(name)>MAXRuleNameLen) {
	printf("name too long or too short.\n");
	return empty;
    }
    
    // Source IP
    printf("source ip and mask [like 127.0.0.1/16]: ");
    scanf("%s",saddr);
    // Source Port
    printf("source port range [like 8080-8031 or any]: ");
    scanf("%s",sport);
    if(strcmp(sport, "any") == 0) {
    	sportMin = 0,sportMax = 0xFFFFu;
    } else {
    	sscanf(sport,"%hu-%hu",&sportMin,&sportMax);
    }
    if(sportMin > sportMax) {
    	printf("the min port > max port.\n");
    	return empty;
    }
    
    // Dest IP
    printf("target ip and mask [like 127.0.0.1/16]: ");
    scanf("%s",daddr);
    // Dest Port
    printf("target port range [like 8080-8031 or any]: ");
    scanf("%s",dport);
    if(strcmp(dport, "any") == 0) {
    	dportMin = 0,dportMax = 0xFFFFu;
    } else {
    	sscanf(dport,"%hu-%hu",&dportMin,&dportMax);
    }
    if(dportMin > dportMax) {
    	printf("the min port > max port.\n");
    	return empty;
    }
    
    // Protocol
    printf("protocol [TCP/UDP/ICMP/any]: ");
    scanf("%s",protoS);
    if(strcmp(protoS,"TCP")==0)
    	proto = IPPROTO_TCP;
    else if(strcmp(protoS,"UDP")==0)
    	proto = IPPROTO_UDP;
    else if(strcmp(protoS,"ICMP")==0)
    	proto = IPPROTO_ICMP;
    else if(strcmp(protoS,"any")==0)
    	proto = IPPROTO_IP;
    else {
    	printf("This protocol is not supported.\n");
    	return empty;
    }
    
    // action
    printf("action [1 for accept,0 for drop]: ");
    scanf("%d",&action);
    
    // log
    printf("is log [1 for yes,0 for no]: ");
    scanf("%u",&log);
    
    printf("result:\n");
    return addFilterRule(after,name,saddr,daddr,
    	(((unsigned int)sportMin << 16) | (((unsigned int)sportMax) & 0xFFFFu)),
    	(((unsigned int)dportMin << 16) | (((unsigned int)dportMax) & 0xFFFFu)),proto,log,action);
}

struct KernelResponse cmdAddNATRule() {
    struct KernelResponse empty;
    char saddr[25],daddr[25],port[15];
    unsigned short portMin,portMax;
    
    empty.code = ERROR_CODE_EXIT;
    printf("ONLY source NAT is supported\n");
    
    // source IP
    printf("source ip and mask [like 127.0.0.1/16]: ");
    scanf("%s",saddr);
    
    // NAT IP
    printf("NAT ip [like 192.168.80.139]: ");
    scanf("%s",daddr);
    
    // destination port
    printf("NAT port range [like 10000-30000 or any]: ");
    scanf("%s",port);
    
    if(strcmp(port, "any") == 0) {
    	portMin = 0,portMax = 0xFFFFu;
    } else {
    	sscanf(port,"%hu-%hu",&portMin,&portMax);
    }
    if(portMin > portMax) {
    	printf("the min port > max port.\n");
    	return empty;
    }
    
    return addNATRule(saddr,daddr,portMin,portMax);
}

void wrongCommand() {
    printf("wrong command.\n");
    printf("uapp <command> <sub-command> [option]\n");
    printf("commands: rule <add | del | ls | default> [del rule's name]\n");
    printf("          nat  <add | del | ls> [del number]\n");
    printf("          ls   <rule | nat | log | connect>\n");
    
    exit(0);
}

int main(int argc, char *argv[]) {
    if(argc<3) {
    	wrongCommand();
    	return 0;
    
    }
    
    struct KernelResponse rsp;
    rsp.code = ERROR_CODE_EXIT;
    
	// firewall rules
	if(strcmp(argv[1], "rule")==0 || argv[1][0] == 'r') {
		if(strcmp(argv[2], "ls")==0 || strcmp(argv[2], "list")==0) {
		// ls
			rsp = getAllFilterRules();
		} else if(strcmp(argv[2], "del")==0) {
		// del
			if(argc < 4)
				printf("Please point rule name in option.\n");
			else if(strlen(argv[3])>MAXRuleNameLen)
				printf("rule name too long!");
			else
				rsp = delFilterRule(argv[3]);
		} else if(strcmp(argv[2], "add")==0) {
		// add
			rsp = cmdAddRule();
		} else if(strcmp(argv[2], "default")==0) {
		// set default
			if(argc < 4)
				printf("Please point default action in option.\n");
			else if(strcmp(argv[3], "accept")==0)
				rsp = setDefaultAction(NF_ACCEPT);
			else if(strcmp(argv[3], "drop")==0)
				rsp = setDefaultAction(NF_DROP);
			else
				printf("No such action. Only \"accept\" or \"drop\".\n");
		} else 
			wrongCommand();
	} else if(strcmp(argv[1], "nat")==0 || argv[1][0] == 'n') {
		if(strcmp(argv[2], "ls")==0 || strcmp(argv[2], "list")==0) {
		// ls NAT
			rsp = getAllNATRules();
		} else if(strcmp(argv[2], "del")==0) {
		// del NAT
			if(argc < 4)
				printf("Please point rule number(seq) in option.\n");
			else {
				int num;
				sscanf(argv[3], "%d", &num);
				rsp = delNATRule(num);
			}
		} else if(strcmp(argv[2], "add")==0) {
		// add NAT
			rsp = cmdAddNATRule();
		} else {
			wrongCommand();
		}
	} else if(strcmp(argv[1], "ls")==0 || argv[1][0] == 'l') {
	// show
		if(strcmp(argv[2],"log")==0 || argv[2][0] == 'l') {
		// log
			unsigned int num = 0;
			if(argc > 3)
				sscanf(argv[3], "%u", &num);
			rsp = getLogs(num);
		} else if(strcmp(argv[2],"con")==0 || argv[2][0] == 'c') {
		// conn
			rsp = getAllConns();
		} else if(strcmp(argv[2],"rule")==0 || argv[2][0] == 'r') {
		// firewall rule
			rsp = getAllFilterRules();
		} else if(strcmp(argv[2],"nat")==0 || argv[2][0] == 'n') {
		// NAT rule
			rsp = getAllNATRules();
		} else
			wrongCommand();
	} else 
		wrongCommand();
		
	dealResponseAtCmd(rsp);
}
