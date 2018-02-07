#ifndef _PCAP2JSON_H
#define _PCAP2JSON_H

#define MAC_LEN 6

typedef struct pcap_hdr_s
{
    uint32_t magic_number;   /* magic number */
    uint16_t vers_major;     /* major version number */
    uint16_t vers_minor;     /* minor version number */
    int32_t  zone;           /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s
{
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct eth_frame_s
{
    uint8_t mac_dst[MAC_LEN]; /* destination MAC address */
    uint8_t mac_src[MAC_LEN]; /* source MAC address */
    uint16_t etype;           /* EtherType (eg, 0x0800 is IPv4), network byte order */
} eth_frame_t;

typedef struct eth_frame_vlan_s
{
    uint8_t mac_dst[MAC_LEN]; /* destination MAC address */
    uint8_t mac_src[MAC_LEN]; /* source MAC address */
    uint16_t tpid;            /* tag protocol identifier (0x8100) */
    uint16_t tci;             /* PCP (3 bits), DEI (1 bit), and VID (12 bits)*/
    uint16_t etype;           /* EtherType (eg, 0x0800 is IPv4), network byte
                                 order */
} eth_frame_vlan_t;

typedef struct ipv4_hdr_s
{
    uint8_t  vers_ihl;       /* version (4 bits) and header length (4 bits) */
    uint8_t  dscp_ecn;
    uint16_t tot_len;        /* packet size, including header and data */
    uint16_t ident;
    uint16_t flags_fragoff;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t hdr_cksum;
    uint32_t addr_src;
    uint32_t addr_dst;
} ipv4_hdr_t;

/* lots of bit fields in the ipv4 header... these macros decode them */
#define IPV4_VERSION(ip4) ((ip4->vers_ihl >> 4) & 0xF)
#define IPV4_HDRLEN(ip4)  (ip4->vers_ihl & 0xF)
#define IPV4_DSCP(ip4)    ((ip4->dscp >> 2) & 0x3F)
#define IPV4_FLAGS(ip4)   ((ip4->flags_fragoff >> 13) & 0x07)
#define IPV4_FRAGOFF(ip4) (ip4->flags_fragoff & 0x1FFF)

typedef struct tcp_seg_s
{
    uint16_t port_src;
    uint16_t port_dst;
    uint32_t seq_no;
    uint32_t ack_no;
    uint16_t flags;
    uint16_t window;
    uint16_t cksum;
    uint16_t urg;
} tcp_seg_t;

#define TCP_DATA_OFFSET(fl) ((fl >> 12) & 0x0F)
#define TCP_FL_FLAGS(fl)    (fl & 0x01FF)

#define TCP_FL_NS(fl)       ((fl >> 8) & 0x01)
#define TCP_FL_CWR(fl)      ((fl >> 7) & 0x01)
#define TCP_FL_ECE(fl)      ((fl >> 6) & 0x01)
#define TCP_FL_URG(fl)      ((fl >> 5) & 0x01)
#define TCP_FL_ACK(fl)      ((fl >> 4) & 0x01)
#define TCP_FL_PSH(fl)      ((fl >> 3) & 0x01)
#define TCP_FL_RST(fl)      ((fl >> 2) & 0x01)
#define TCP_FL_SYN(fl)      ((fl >> 1) & 0x01)
#define TCP_FL_FIN(fl)      (fl & 0x01)


typedef struct udp_seg_s
{
    uint16_t port_src;       /* source port (optional, may be 0x0000) */
    uint16_t port_dst;       /* dest port */
    uint32_t len;            /* length of header + data */
    uint32_t cksum;          /* checksum (optional, may be 0x0000) */
} udp_seg_t;

struct Globals
{
    int include_mac;
    int flags_array;
} glb;

char *format_mac(uint8_t *mac, char *mac_buf);
char *format_ipv4_addr(uint32_t ipv4_addr, char *addr_buf);
void do_tcp_segment(void *payload);
void do_udp_segment(void *payload);
void do_ip4_payload(void *payload);
void do_ip6_payload(void *payload);
void do_eth_frame(eth_frame_t *ethp);

#endif
