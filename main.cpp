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

    printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
	*(packet + 0), *(packet + 1), *(packet + 2), *(packet + 3), *(packet + 4), *(packet + 5));
    printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n\n",
	*(packet + 6), *(packet + 7), *(packet + 8), *(packet + 9), *(packet + 10), *(packet + 11));
 
    if(ntohs(*(uint16_t*)(packet + 12)) == 0x0800){
	    printf("[ IP packet detected ]\n");

	    const u_char* ip_packet = packet + 14;	// start of ip header
	    int ip_len = (int)(*(uint8_t*)ip_packet & 0x0F) << 2; // ip header length
	    
	    printf("src ip : %u.%u.%u.%u\n",
		*(ip_packet + 12), *(ip_packet + 13), *(ip_packet + 14), *(ip_packet + 15));
	    printf("dst ip : %u.%u.%u.%u\n\n",
		*(ip_packet + 16), *(ip_packet + 17), *(ip_packet + 18), *(ip_packet + 19));

	    if(*(uint8_t*)(ip_packet + 9) == 0x06){
		    printf("[ TCP packet detected ]\n");

		    const u_char* tcp_packet = ip_packet + ip_len;	// start of tcp header
		    int tcp_len = (int)(*(uint8_t*)(tcp_packet + 12) & 0xF0) >> 2;	// tcp header length

		    printf("src port : %u\n", ntohs(*(uint16_t*)tcp_packet));
		    printf("dst port : %u\n\n", ntohs(*(uint32_t*)(tcp_packet + 2)));

		    const u_char* data = tcp_packet + tcp_len;

		    int data_len = (packet + header->caplen - data < 32)
			    ?(packet + header->caplen - data):32;	// choose min(data_size, 32);

		    if(data_len == 0){
			    printf("no data\n\n");
		    }
		    else{
		    	printf("data (up to 32 bytes)");

			    for(i = 0; i < data_len; i++){
				    if(i % 16 == 0) printf("\n");
				    printf("%02x ", *(data + i));
			    }
			    printf("\n\n");
		    }

	    }
    }

    
  }

  pcap_close(handle);
  return 0;
}
