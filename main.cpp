#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("----------%u bytes captured----------\n", header->caplen);
    
    int i;
    for(i = 0; i < header->caplen; i++){
	    printf("%02x ", *(packet + i));
    }
    printf("\n\n");

    printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
	*(packet + 0), *(packet + 1), *(packet + 2), *(packet + 3), *(packet + 4), *(packet + 5));
    printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n\n",
	*(packet + 6), *(packet + 7), *(packet + 8), *(packet + 9), *(packet + 10), *(packet + 11));
 
    if(ntohs(*(uint16_t*)(packet+12)) == 0x0800){
	    printf("IP packet detected\n");
    }

    
  }

  pcap_close(handle);
  return 0;
}
