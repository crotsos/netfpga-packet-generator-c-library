//MaM#include "nf_pktgen.h"
#include <unistd.h>

#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

struct pktgen_hdr {
  uint32_t magic;
  uint32_t seq_num;
  uint32_t tv_sec;
  uint32_t tv_usec;
  struct timeval time;
};

//check here whether the pktgen format is correct
uint32_t
extract_pktgen_pkt_id(const char *b, int len) {
  struct ether_header *ether = (struct ether_header *)b;
  struct pktgen_hdr *pktgen;
  uint8_t *data = b;
  
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
  pcap_t *pcap_dev;
  char errbuf[PCAP_ERRBUF_SIZE];

  int first = 1;
  uint64_t delay_pcap, delay_oflops, oflops_ts, start_oflops;
  struct timeval start_pcap;

  //temporary packet buffers 
  struct pcap_pkthdr header; // The header that pcap gives us 
  const u_char *packet; // The actual packet 


  if(argc < 2) {
    fprintf(stderr, "no trace provided\n");
  }

  printf("reading file %s\n", argv[1]);
  pcap_dev = pcap_open_offline(argv[1], errbuf);

  if(!pcap_dev) {
    fprintf(stderr, "pcap_open_offline:%s\n", errbuf);
    exit(1);
  }

  
  while (packet = pcap_next(pcap_dev, &header)) { 

    //set timestamp of packet
    memcpy(&oflops_ts, packet + 16, sizeof(uint64_t));
    oflops_ts = ntohll(oflops_ts);

    if(first) {
      memcpy(&start_pcap, &header.ts, sizeof(struct timeval));
      start_oflops = oflops_ts;
      first = 0;
    }

    delay_pcap = (uint64_t)(header.ts.tv_sec - start_pcap.tv_sec)*1000000000 + 
      (uint64_t)(header.ts.tv_usec - start_pcap.tv_usec)*1000;
    delay_oflops = oflops_ts - start_oflops;

    printf("%d %lld %lld %d\n", extract_pktgen_pkt_id(packet + 24, header.len -24), delay_pcap, delay_oflops, (delay_oflops - delay_pcap));
  }



}
