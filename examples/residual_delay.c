#include "nf_pktgen.h"
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define INTERPACKET_DELAY 1000
#define PKT_COUNT 1000
#define CORRECTION 0.999972

/* struct pktgen_hdr { */
/*   uint32_t magic; */
/*   uint32_t seq_num; */
/*   uint32_t tv_sec; */
/*   uint32_t tv_usec; */
/*   struct timeval time; */
/* }; */

//check here whether the pktgen format is correct
uint32_t
extract_pktgen_pkt_id(const char *b, int len) {
  struct ether_header *ether = (struct ether_header *)b;
  struct pktgen_hdr *pktgen;
  uint8_t *data = (uint8_t *)b;
  
  if (ntohs(ether->ether_type) != 0x0800) {
    fprintf(stderr, "Invalid ether type\n");
    return 0;
  }

  b = b + sizeof(struct ether_header);
  len -= sizeof(struct ether_header);
  

  struct iphdr *ip_p = (struct iphdr *) b;
  if (len < 4*ip_p->ihl) {
    printf("capture too small for ip: %d\n", len);
    return 0;
  }
  b = b + 4*ip_p->ihl;
  len -=  4*ip_p->ihl;

  //tcp/udp fields
  struct udphdr *udp_p = (struct udphdr *)b;

  b += sizeof(struct udphdr);
  pktgen = (struct pktgen_hdr *)b;

  return ntohl(pktgen->seq_num);
}

uint64_t
ntohll(uint64_t val) {
  uint64_t ret = 0;

  ret=((val & 0x00000000000000FF) << 56) |
    ((val & 0x000000000000FF00) << 40) |
    ((val & 0x0000000000FF0000) << 24) |
    ((val & 0x00000000FF000000) << 8)  |
    ((val & 0x000000FF00000000) >> 8)  |
    ((val & 0x0000FF0000000000) >> 24) |
    ((val & 0x00FF000000000000) >> 40) |
    ((val & 0xFF00000000000000) >> 56);

  return ret;
}
  
int
main(int argc, char *argv[]) {
  char errbuf[PCAP_ERRBUF_SIZE];

  char *pkt_buf;
  int pkt_len = 150;

  struct pcap_pkthdr h;
  pcap_t *handle;
  int handle_fd;
  struct ether_header *eth;
  struct iphdr *ip;
  struct udphdr *udp;

  int first = 1, i;
  uint64_t snd_ts, rcv_ts;

  //temporary packet buffers 
  struct pcap_pkthdr *header; // The header that pcap gives us 
  const u_char *packet; // The actual packet 
  struct nf_cap_stats stat;
  struct pktgen_hdr *ret;
  int pkt_count;
  int pkt_delay;

  fd_set set;
  struct timeval timeout;

  if(argc < 4) {
    fprintf(stderr, "Output file is not defined \n usage: ./residual_delay pkt_count pkt_delay output_file");
    exit(1);
  }
  
  FILE *output = fopen(argv[3], "w");
  if(output == NULL) {
    perror("fopen");
    exit(1);
  }

  pkt_count = atoi(argv[1]);
  if(pkt_count <= 0) {
    printf("Invalid number of packet %s\n", argv[1]);
    exit(1);
  }

  pkt_delay = atoi(argv[2]);
  if(pkt_delay <= 0) {
    printf("Invalid packet delay %s\n", argv[2]);
    exit(1);
  }

  //enable paddin
  nf_init(1, 1, 1); 

  for (i = 0; i < 4; i++) 
      nf_gen_reset_queue(i);

  h.len = pkt_len;
  h.caplen = pkt_len;
  h.ts.tv_sec = 0;
  h.ts.tv_usec = 0;

  pkt_buf = (char *)xmalloc(pkt_len*sizeof(char));
  bzero(pkt_buf, pkt_len*sizeof(char));
  eth = (struct ether_header *)pkt_buf;
  memcpy(eth->ether_shost, "\x11\x11\x11\x11\x11\x11", ETH_ALEN);
  memcpy(eth->ether_dhost, "\x22\x22\x22\x22\x22\x22", ETH_ALEN);
  eth->ether_type = htons(ETHERTYPE_IP);
  
  ip = (struct ip *)(pkt_buf + sizeof(struct ether_header));
  ip->ihl=5;
  ip->version=4;
  ip->tot_len=htons(pkt_len - sizeof(struct ether_header)); 
  ip->ttl = 100;
  ip->protocol = IPPROTO_UDP; //udp protocol
  ip->saddr = inet_addr("10.1.1.1"); 
  ip->daddr = inet_addr("10.1.1.2"); //test.nw_dst;
  ip->check=0;
  //  ip->check=htons(ip_sum_calc(20, (void *)state->ip));
  
  udp = (struct udphdr *)(struct ip *)(pkt_buf + sizeof(struct ether_header) + 
				       sizeof(struct ip));
  udp->source = htons(8080);
  udp->dest = htons(8080);
  udp->len = htons(pkt_len - sizeof(struct ether_header) - sizeof(struct ip)); 
  
  nf_gen_set_number_iterations (pkt_count, 1, 3);
  nf_gen_load_packet(&h,pkt_buf, 3, pkt_delay); 
  
  handle = pcap_open_live("nf2c0", 128, 1, 1, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", "nf2c0", errbuf);
    return(2);
  }
  
  if(pcap_setnonblock(handle, 1, errbuf) < 0) {
    fprintf(stderr, "Couldn't set device %s non block: %s\n", "nf2c0", errbuf);
    return(2);
  }
  
  if((handle_fd = pcap_get_selectable_fd(handle)) < 0) {
    fprintf(stderr, "Couldn't set device %s get fd: %s\n", "nf2c0", errbuf);
    return(2);
  }
  
  /* Initialize the file descriptor set. */
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;
  FD_ZERO (&set);
  FD_SET (handle_fd, &set);

  nf_start(0);  

  while (select (FD_SETSIZE, &set, NULL, NULL, &timeout) > 0) {  
    if(pcap_next_ex(handle, &header, &packet) < 1) 
      break;

    //set timestamp of packet 
    memcpy(&rcv_ts, packet + 16, sizeof(uint64_t)); 
    rcv_ts = CORRECTION*ntohll(rcv_ts); 

    ret = (struct pktgen_hdr *)((uint8_t *)packet + 88);
    snd_ts =  CORRECTION*((((uint64_t)ntohl(ret->tv_sec)) << 32) |  
			  ((0xFFFFFFFF) & ((uint64_t)ntohl(ret->tv_usec))));
    
    fprintf(output, "%lu %lld %lld %lld\n", htonl(ret->seq_num), rcv_ts, snd_ts,rcv_ts - snd_ts); 

    /* Initialize the file descriptor set. */
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    FD_ZERO (&set);
    FD_SET (handle_fd, &set);
  }

  nf_finish();

  nf_cap_stat(0, &stat);
  printf("rcv:%u:%u\n", stat.pkt_cnt, stat.capture_packet_cnt);

  fclose(output);
}
