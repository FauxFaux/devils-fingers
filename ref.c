#include <pcap.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  pcap_t *handle;                /* Session handle */
  char *dev;                     /* The device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
  struct bpf_program fp;         /* The compiled filter */
  char filter_exp[] = "port 80"; /* The filter expression */
  struct pcap_pkthdr header;     /* The header that pcap gives us */
  const u_char *packet;          /* The actual packet */

  /* Define the device */
  dev = "any";

  /* Open the session in promiscuous mode */
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return (2);
  }
  /* Compile and apply the filter */
  if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
            pcap_geterr(handle));
    return (2);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp,
            pcap_geterr(handle));
    return (2);
  }
  while (1){
      /* Grab a packet */
      packet = pcap_next(handle, &header);
      /* Print its length */
      printf("Jacked a packet with length of [%d]\n", header.len);
  }
  /* And close the session */
  pcap_close(handle);
  return (0);
}
