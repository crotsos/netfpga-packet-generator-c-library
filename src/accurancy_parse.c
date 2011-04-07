//MaM#include "nf_pktgen.h"

#include <pcap/pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>


struct pktgen_hdr {
  uint32_t magic;
  uint32_t seq_num;
  uint32_t tv_sec;
  uint32_t tv_usec;
  struct timeval time;
};

//check here whether the pktgen format is correct
uint32_t
extract_pktgen_pkt_id(unsigned char *b, int len) {
  struct ether_header *ether = (struct ether_header *)b;
  struct pktgen_hdr *pktgen;
  uint8_t *data = b;
  
  if (ntohs(ether_vlan->ether_type) != 0x0800) {
    fprintf("Invalid ether type\n");
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
  fl->tp_src = ntohs(udp_p->source);
  fl->tp_dst = ntohs(udp_p->dest);

  b += sizeof(struct udphdr);
  pktgen = (struct pktgen_hdr *)b;

  return ntohl(pktgen->seq_num);
}
  
int
main(int argc, char *argv[]) {
  pcap_t *pcap_dev;
  char errbuf[PCAP_ERRBUF_SIZE];

  //temporary packet buffers 
  struct pcap_pkthdr header; // The header that pcap gives us 
  const u_char *packet; // The actual packet 

  if(argc < 1) {
    fprintf("no trace provided\n");
  }


  pcap_dev = pcap_open_offline(ARGV[0], errbuf);

  if(!pcap_dev) {
    fprintf(stderr, "pcap_open_offline:%s\n", errbuf);
    exit(1);
  }

  
  while (packet = pcap_next(handle,&header)) { 
    
  }



}
