#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <linux/if_link.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define NAME_SIZE 20
#define MACADDR_STRLEN 18
#define IPADDR_STRLEN 30
#define SIZE 100
static const char *mac_ntoa(u_int8_t *d);
static const char *ip_ntoa(void *i);
static void MAC_address(u_int32_t length, const u_char *content);
static void ip_packet(struct ip *ip);

struct ip_address
{
    char src_ip[IPADDR_STRLEN];
    char dst_ip[IPADDR_STRLEN];
    int count;
};
typedef struct ip_address ip_address;
ip_address table[SIZE];
int num_ip=0;
int ptr=0;

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char filename[NAME_SIZE];
    strcpy(filename,argv[2]);

    pcap_t *handle=pcap_open_offline(filename, errbuf);
    if(!handle){
        fprintf(stderr, "pcap_open_offline(): %s\n",errbuf);
        exit(1);
    }

    printf("===== OPEN %s =====\n",filename);
    
    //the amount of total packets
    int total=0;
    memset(&table,0,sizeof(table));

    //read packets
    while(1)
    {
        struct pcap_pkthdr *header=NULL;
        const u_char *content=NULL;
        int ret;
        //catch packet
        //if success return 1,failed return -1, timeout return 0, no package return -2
        ret=pcap_next_ex(handle, &header, &content);
        if(ret==1)
        {
            struct tm *ltime;
            char timestr[50];
            time_t local_tv_sec;

            local_tv_sec=header->ts.tv_sec;
            ltime=localtime(&local_tv_sec);
            strftime(timestr,sizeof timestr, "%Y/%m/%d %H:%M:%S",ltime);

            total++;
            //print TIME
            printf("NUMBER %d Packet\n",total);
            printf("===================== TIME ======================\n");
            printf("TIME: %s.%.6d\n",timestr, (int)header->ts.tv_usec);
            MAC_address(header->caplen,content);
            printf("\n\n");
        }
        else if(ret==0)
        {
            printf("Timeout!\n");
        }
        else if(ret==-1)
        {
            fprintf(stderr, "pcap_next_ex(): %s\n", pcap_geterr(handle));
        }
        else if(ret==-2)
        {
            printf("No more packet from %s!\n",filename);
            break;
        }
    }
    printf("*************************************************\n");
    for(int i=0; i<ptr; i++)
    {
        printf("[%s ~ %s]: %d\n",table[i].src_ip,table[i].dst_ip,table[i].count);
    }
    printf("TOTAL IP PACKETS: %d\n",num_ip);
    printf("*************************************************\n");
    printf("TOTAL PACKET %d\n",total);

    //free
    pcap_close(handle);
    return 0;
}

static const char *mac_ntoa(u_int8_t *d) 
{

    #define STR_BUF 16
    static char mac[STR_BUF][MACADDR_STRLEN];
    static int which = -1;

    which = (which + 1 == STR_BUF ? 0 : which + 1);

    memset(mac[which], 0, MACADDR_STRLEN);
    snprintf(mac[which], sizeof(mac[which]), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return mac[which];
}

static const char *ip_ntoa(void *i) 
{

    static char ip[STR_BUF][INET_ADDRSTRLEN];
    static int which = -1;

    which = (which + 1 == STR_BUF ? 0 : which + 1);

    memset(ip[which], 0, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, i, ip[which], sizeof(ip[which]));

    return ip[which];
}

static void MAC_address(u_int32_t length, const u_char *content)
{
    char src_mac[MACADDR_STRLEN]={0}; //source address
    char dst_mac[MACADDR_STRLEN]={0}; //destination address
    u_int64_t type;
    

    struct ether_header *ethernet=(struct ether_header *)content;
    type=ntohs(ethernet->ether_type);

    //copy header
    snprintf(src_mac, sizeof(src_mac), "%s",mac_ntoa(ethernet->ether_shost));
    snprintf(dst_mac, sizeof(dst_mac), "%s",mac_ntoa(ethernet->ether_dhost));

    //print MAC address
    printf("================== MAC ADDRESS ==================\n");
    printf("Source MAC Address: %s\n",src_mac);
    printf("Destination MAC Address: %s\n",dst_mac);
    //printf("=================================================\n");
    
    if(type==ETHERTYPE_IP)
    {
        printf("=================== IP PACKET ===================\n");
        ip_packet((struct ip *)(content+ETHER_HDR_LEN));
        printf("=================================================\n");
        num_ip++;
    }
}

static void udp_packet(struct udphdr *udp)
{
    u_int16_t src_port=ntohs(udp->uh_sport);
    u_int16_t dst_port=ntohs(udp->uh_dport);

    //print port
    printf("Source Port: %5u\n", src_port);
    printf("Destination Port: %5u\n",dst_port);
}

static void tcp_packet(struct tcphdr *tcp)
{
    u_int16_t src_port=ntohs(tcp->th_sport);
    u_int16_t dst_port=ntohs(tcp->th_dport);

    //print port
    printf("Source Port: %5u\n",src_port);
    printf("Destination Port: %5u\n",dst_port);
}

static void ip_packet(struct ip *ip)
{
    u_char protocol=ip->ip_p;
    char src_ip[IPADDR_STRLEN]={0};
    char dst_ip[IPADDR_STRLEN]={0};

    //copy ip address
    snprintf(src_ip, sizeof(src_ip),"%s",ip_ntoa(&ip->ip_src));
    snprintf(dst_ip, sizeof(dst_ip),"%s",ip_ntoa(&ip->ip_dst));

    //統計每對(來源IP,目的IP)的封包數量
    int check=0;
    for(int i=0; i<SIZE; i++)
    {
        if((strcmp(table[i].src_ip,src_ip)==0)&&(strcmp(table[i].dst_ip,dst_ip)==0))
        {
            //printf("2\n");
            table[i].count++;
            check=1;
            break;
        }
    }
    if(check!=1)
    {
        strcpy(table[ptr].src_ip,src_ip);
        strcpy(table[ptr].dst_ip,dst_ip);
        table[ptr].count++;
        ptr++;
    }
    //printf("%d\n",table[0].count);
    //print ip address
    printf("Source IP Address: %s\n",src_ip);
    printf("Destination IP Address: %s\n",dst_ip);

    char *p=(char *)ip+(ip->ip_hl<<2);
    if(protocol==IPPROTO_UDP)
    {   
        printf("Protocol: UDP\n");
        udp_packet((struct udphdr *)p);
    }
    if(protocol==IPPROTO_TCP)
    {
        printf("Protocol: TCP\n");
        tcp_packet((struct tcphdr *)p);
    }
}