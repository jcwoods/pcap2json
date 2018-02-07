#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "pcap2json.h"

static int initialize(int argc, char **argv);
static int doFile(FILE *pcap);


static int initialize(int argc, char **argv)
{
    int argn;

    memset(&glb, 0x00, sizeof(glb));

    for (argn = 1; argn < argc; argn++)
    {
        if (strcmp(argv[argn], "--mac") == 0)
        {
            glb.include_mac = 1;
        }
        else if (strcmp(argv[argn], "--flags-array") == 0)
        {
            glb.flags_array = 1;
        }
        else
        {
            break;
        }
    }

    return argn;
}

char *format_mac(uint8_t *mac, char *mac_buf)
{
    int i;
    int mboff;

    for (i = 0, mboff = 0; i < MAC_LEN; i++, mboff += 2 )
    {
        if (i > 0) mac_buf[mboff++] = ':';
        sprintf(&mac_buf[mboff], "%02x", (unsigned int) mac[i]);
    }

    mac_buf[mboff] = '\0';
    return mac_buf;
}

char *format_ipv4_addr(uint32_t ipv4_addr, char *addr_buf)
{
    struct in_addr ipaddr;
    ipaddr.s_addr = ipv4_addr;
    strcpy(addr_buf, inet_ntoa(ipaddr));
    return addr_buf;
}

void do_tcp_segment(void *payload)
{
    uint16_t port_src, port_dst;
    tcp_seg_t *tcp = (tcp_seg_t *) payload;

    port_src = ntohs(tcp->port_src);
    port_dst = ntohs(tcp->port_dst);

    uint16_t flags = TCP_FL_FLAGS(ntohs(tcp->flags));

    printf(", \"src_port\": %d, \"dst_port\": %d", port_src, port_dst);

    if (glb.flags_array == 1)
    {
        printf(", \"tcp_flags\": [ \"0x%04x\"", flags);
        if (TCP_FL_NS(flags) != 0)  printf(", \"NS\"");
        if (TCP_FL_CWR(flags) != 0) printf(", \"CWR\"");
        if (TCP_FL_ECE(flags) != 0) printf(", \"ECE\"");
        if (TCP_FL_URG(flags) != 0) printf(", \"URG\"");
        if (TCP_FL_ACK(flags) != 0) printf(", \"ACK\"");
        if (TCP_FL_PSH(flags) != 0) printf(", \"PSH\"");
        if (TCP_FL_RST(flags) != 0) printf(", \"RST\"");
        if (TCP_FL_SYN(flags) != 0) printf(", \"SYN\"");
        if (TCP_FL_FIN(flags) != 0) printf(", \"FIN\"");
        printf("]");
    }
    else
    {
        printf(", \"ns_flag\": %d", TCP_FL_NS(flags));
        printf(", \"cwr_flag\": %d", TCP_FL_CWR(flags));
        printf(", \"ece_flag\": %d", TCP_FL_ECE(flags));
        printf(", \"urg_flag\": %d", TCP_FL_URG(flags));
        printf(", \"ack_flag\": %d", TCP_FL_ACK(flags));
        printf(", \"psh_flag\": %d", TCP_FL_PSH(flags));
        printf(", \"rst_flag\": %d", TCP_FL_RST(flags));
        printf(", \"syn_flag\": %d", TCP_FL_SYN(flags));
        printf(", \"fin_flag\": %d", TCP_FL_FIN(flags));
    }

    return;
}

void do_udp_segment(void *payload)
{
    uint16_t port_src, port_dst;
    udp_seg_t *udp = (udp_seg_t *) payload;

    port_src = ntohs(udp->port_src);
    port_dst = ntohs(udp->port_dst);

    printf(", \"src_port\": %d, \"dst_port\": %d", port_src, port_dst);
    return;
}

void do_ip4_payload(void *payload)
{
    ipv4_hdr_t *iph = (ipv4_hdr_t *) payload;
    void (*do_segment)(void *) = NULL;
    char ipbuf[20];
    char *type;

    printf(", \"src_ip\": \"%s\"", format_ipv4_addr(iph->addr_src, ipbuf));
    printf(", \"dst_ip\": \"%s\"", format_ipv4_addr(iph->addr_dst, ipbuf));
    printf(", \"ip_len\": %d", ntohs(iph->tot_len));

    type = NULL;
    switch (iph->protocol)
    {
        case 0x06:         /* TCP */
            type = "TCP";
            do_segment = do_tcp_segment;
            break;

        case 0x11:         /* UDP */
            type = "UDP";
            do_segment = do_udp_segment;
            break;

        default:
            type = "Other";
            do_segment = NULL;
    }

    printf(", \"ip_type\": \"%s\"", type);

    payload = &iph[1];
    if (do_segment != NULL) do_segment(payload);

    return;
}

void do_ip6_payload(void *payload)
{
#if 0
    ipv6_hdr_t *iph = (ipv6_hdr_t *) payload;

    char ipbuf[20];

    printf("    src_ip: %s\n", format_ipv4_addr(iph->addr_src, ipbuf));
    printf("    dst_ip: %s\n", format_ipv4_addr(iph->addr_dst, ipbuf));
    /* printf("    length: %d\n",      */
#endif

    return;
}

void do_eth_frame(eth_frame_t *ethp)
{
    char mac_buf[24];
    void (*do_payload)(void *) = NULL;
    char *type;
    uint16_t etype;
    uint8_t  *payload;

    if (glb.include_mac)
    {
        printf(", \"src_mac\": \"%s\"", format_mac(ethp->mac_src, mac_buf));
        printf(", \"dst_mac\": \"%s\"", format_mac(ethp->mac_dst, mac_buf));
    }

    etype = ntohs(ethp->etype);
    payload = (uint8_t *) &ethp[1];

    if (etype == 0x8100) /* 802.1Q (VLAN tag)? */
    {
        etype = ntohs(((eth_frame_vlan_t *) ethp)->etype);

        /* payload slides four (or more) bytes due to larger 
           ethernet header... recompute */
        payload = (uint8_t *) &((eth_frame_vlan_t *) ethp)[1];
    }

    switch (etype)
    {
        case 0x0800:
            type = "IPv4";
            do_payload = do_ip4_payload;
            break;

        case 0x0806:
            type = "ARP";
            break;

        case 0x86DD: type = "IPv6"; break;
            type = "IPv4";
            do_payload = do_ip6_payload;
            break;

        default:
            type = "Other";
    }

    printf(", \"eth_type\": \"%s\"", type);
    if (do_payload != NULL) do_payload(payload);
    
    return;
}

static int doFile(FILE *pcap)
{
    pcap_hdr_t ghdr;
    pcaprec_hdr_t rhdr;
    eth_frame_t *ethp;
    uint8_t *buf;

    if (fread(&ghdr, sizeof(ghdr), 1, pcap) != 1)
    {
        fprintf(stderr, "ERROR: fread(ghdr): %s\n", strerror(errno));
        return 2;
    }

    buf = alloca(ghdr.snaplen);
    if (buf == (uint8_t *) NULL)
    {
        fprintf(stderr, "ERROR: malloc(buf): %s\n", strerror(errno));
        exit(1);
    }

    while (fread(&rhdr, sizeof(rhdr), 1, pcap) == 1)
    {

        if (fread(buf, rhdr.incl_len, 1, pcap) != 1)
        {
            fprintf(stderr, "ERROR: fread(): %s\n", strerror(errno));
            exit(1);
        }

        ethp = (eth_frame_t *) buf;
        printf("{ \"time\": %06d.%06d", rhdr.ts_sec, rhdr.ts_usec);
        do_eth_frame(ethp);
        printf("}\n");
    }

    if (errno != 0)
    {
        fprintf(stderr, "ERROR: fread(buf): %s\n", strerror(errno));
        exit(1);
    }

    return 0;
}

int main(int argc, char **argv)
{
    int argn;
    FILE *pcap;

    argn = initialize(argc, argv);

    if (argn == argc)     /* use stdin rather than files from command line */
    {
        doFile(stdin);
    }
    else
    {
        while (argn < argc)
        {
            pcap = fopen(argv[argn], "r");
            if (pcap == NULL) return 1;

            doFile(pcap);

            fclose(pcap);
            argn++;
        }
    }

    return 0;
}
