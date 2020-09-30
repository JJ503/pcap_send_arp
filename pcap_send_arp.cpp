#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>


struct arp{
    unsigned char ar_hdr[2];      // hw type  2 byte
    unsigned char ar_p[2];        // protocol  2 byte
    unsigned char ar_hl;        // hw length  1 byte
    unsigned char ar_pl;        // protocol length  1 byte
    unsigned char ar_op[2];       // option code  2 byte
    unsigned char ar_smac[6];  // sender mac  6 byte
    unsigned char ar_sip[4];      // sender ip  4 byte
    unsigned char ar_tmac[6];  // target mac  6 byte
    unsigned char ar_tip[4];      // target ip  4 byte
};

int main(int argc, char **argv)
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[100];
    int i;

    /* Check the validity of the command line */
    if (argc != 2)
    {
        printf("usage: %s interface (e.g. 'rpcap://eth0')", argv[0]);
        return -1;
    }
     
    /* Open the output device */
    if ( (fp= pcap_open_live(argv[1],            // name of the device
                        100,                // portion of the packet to capture (only the first 100 bytes)
                        PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode
                        1000,               // read timeout
                        errbuf              // error buffer
                        ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);
        return -1;
    }
 
    /* Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1 */
    packet[0]=1;
    packet[1]=1;
    packet[2]=1;
    packet[3]=1;
    packet[4]=1;
    packet[5]=1;
    
    /* set mac source to 2:2:2:2:2:2 */
    packet[6]=2;
    packet[7]=2;
    packet[8]=2;
    packet[9]=2;
    packet[10]=2;
    packet[11]=2;

    // Eth type = ARP => 0806
    packet[12] = 0x08;
    packet[13] = 0x06;

    // ARP 패킷 채우기
    struct arp arp;
    // arp hw type = 1 (이더넷)
    arp.ar_hdr[0] = 0x00;
    arp.ar_hdr[1] = 0x01;

    // protocol type = 0800 (ip)
    arp.ar_p[0] = 0x08;
    arp.ar_p[1] = 0x00;

    // hw length = 6 (mac 주소 길이)
    arp.ar_hl = 0x06; 
    
    // protocol length = 4 (ip 주소 길이)
    arp.ar_pl = 0x04;

    // operation = 0001 (request)
    arp.ar_op[0] = 0x00;
    arp.ar_op[1] = 0x01;
    
    // Sender MAC = 2:2:2:2:2:2
    arp.ar_smac[0] = 0x02;
    arp.ar_smac[1] = 0x02;
    arp.ar_smac[2] = 0x02;
    arp.ar_smac[3] = 0x02;
    arp.ar_smac[4] = 0x02;
    arp.ar_smac[5] = 0x02;

    // Sender IP = 1.2.3.4
    arp.ar_sip[0] = 0x01;
    arp.ar_sip[1] = 0x02;
    arp.ar_sip[2] = 0x03;
    arp.ar_sip[3] = 0x04;

    // Target MAC = 1:1:1:1:1:1
    arp.ar_tmac[0] = 0x01;
    arp.ar_tmac[1] = 0x01;
    arp.ar_tmac[2] = 0x01;
    arp.ar_tmac[3] = 0x01;
    arp.ar_tmac[4] = 0x01;
    arp.ar_tmac[5] = 0x01;

    // Target MAC = 5.6.7.8
    arp.ar_tip[0] = 0x05;
    arp.ar_tip[1] = 0x06;
    arp.ar_tip[2] = 0x07;
    arp.ar_tip[3] = 0x08;

    memcpy(packet + 14, &arp, sizeof(struct arp));

    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, sizeof(struct arp) + 14) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
        return -1;
    }
    else
        printf("Success sending the packet\n");

    return 0;
}
