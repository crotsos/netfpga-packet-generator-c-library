#include "nf_pktgen.h"
  
int
main(int argc, char *argv[]) {
  int i;
  uint64_t count = 0;
  uint8_t *data;
  struct pcap_pkthdr h;
  struct timeval start, now;
  struct nf_cap_stats stat;

  printf("Initiating packet generator\n");

  //enable padding
  nf_init(1, 0, 1); 

  struct nf_cap_t * cap2 = nf_cap_enable("nf2c1", 128);
  if(cap2 == NULL) {
    perror("nf_cap_enable");
  }

  nf_start(0);
  gettimeofday(&now, 0);
  gettimeofday(&start, 0);

  //open file to save data
  //pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname);


  while( now.tv_sec - start.tv_sec < 3600){
    //if( (data = nf_cap_next(cap2, &h)) != NULL)
    //  printf("packet %lld,%u.%06u \n", ++count, h.ts.tv_sec, h.ts.tv_usec);   
    sleep(60);
    gettimeofday(&now, 0); 
  }

  printf("finished capturing\n");
  
  // Wait until the correct number of packets is sent
  nf_finish();

  nf_cap_stat(1, &stat);
  printf("rcv:%u:%u\n", stat.pkt_cnt, stat.capture_packet_cnt);

  return 0;

}


