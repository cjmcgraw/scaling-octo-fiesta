#include <stdio.h>
#include <pcap.h>

# define MAX_BUF_SIZE 65535

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int i;
    printf("got packet!\n");
    printf("args: %s\n", args);
    printf("headers:\n");
    printf("  caplen: %d\n", header->caplen);
    printf("  len: %d\n", header->len);
    printf("  ts: %d\n", header->ts.tv_sec);
    printf("\n");
    //printf("packet:\n");
    //for (i = 0; i < header->len; i++) {
    //    if (i > 0 && i % 8 == 0) {
    //        printf("\n");
    //    }
    //    printf("%02x ", packet[i]);
    //}
    //printf("\n");
    printf("\n");

    if (header->len < header->caplen) {
        printf("packet was trimmed!\n  len: %d\n  caplen: %d\n", header->len, header->caplen);
    }
}

int main(int argc, char *argv[]) {
    char *device_name = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *dev;
    struct bpf_program fp;
    char filter_exp[] = "port 80";
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    u_char *packet;

    if (pcap_lookupnet(device_name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device: %s\nERROR: %s\n", device_name, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(device_name, MAX_BUF_SIZE, 1, 10, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Coulnd't open device: %s\nERROR: %s\n", device_name, errbuf);
        return(2);
    }

    //if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    //    fprintf(stderr, "Couldn't parse filter %s:\nERROR: %s\n", filter_exp, pcap_geterr(handle));
    //    return(2);
    //}

    //if (pcap_setfilter(handle, &fp) == -1) {
    //    fprintf(stderr, "Couldn't install filter %s\nERROR: %s\n", filter_exp, pcap_geterr(handle));
    //    return(2);
    //}
    
    printf("starting packet pulling loop\n");
    pcap_loop(handle, 10000, process_packet, "qq");
    printf("finished packet pulling loop!\n");
    pcap_close(handle);


    printf("finished\n");
    printf("\n");
    return(0);
}
