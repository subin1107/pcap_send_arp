#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>

struct arp{
    unsigned char arp_hdr[2]; //hardware type
    unsigned char arp_pro[2]; //protocol type
    unsigned char arp_hl;     //hardware length
    unsigned char arp_pl;     //protocol length
    unsigned char arp_op[2];  //op code
    unsigned char arp_smac[6];//sender mac
    unsigned char arp_sip[4]; //sender ip
    unsigned char arp_tmac[6];//target mac
    unsigned char arp_tip[4]; //target ip
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
    
    packet[12]=0x08;
    packet[13]=0x06;

    /* Fill the rest of the packet */
    for(i=14;i<100;i++)
    {
        packet[i]=i%256;
    }

    struct arp arp;

    arp.arp_hdr[0]=0x00;
    arp.arp_hdr[1]=0x01;

    arp.arp_pro[0]=0x08;
    arp.arp_pro[1]=0x00;

    arp.arp_hl=0x06;
    arp.arp_pl=0x04;

    arp.arp_op[0]=0x00;
    arp.arp_op[1]=0x01;


    /* sender mac 3:3:3:3:3:3 */
    arp.arp_smac[0]=0x03;
    arp.arp_smac[1]=0x03;
    arp.arp_smac[2]=0x03;
    arp.arp_smac[3]=0x03;
    arp.arp_smac[4]=0x03;
    arp.arp_smac[5]=0x03;

    /* sender ip 3:3:3:3 */
    arp.arp_sip[0]=0x03;
    arp.arp_sip[1]=0x03;
    arp.arp_sip[2]=0x03;
    arp.arp_sip[3]=0x03;

    /* target mac 4:4:4:4:4:4 */
    arp.arp_tmac[0]=0x04;
    arp.arp_tmac[1]=0x04;
    arp.arp_tmac[2]=0x04;
    arp.arp_tmac[3]=0x04;
    arp.arp_tmac[4]=0x04;
    arp.arp_tmac[5]=0x04;

    /* target ip 4:4:4:4 */
    arp.arp_tip[0]=0x04;
    arp.arp_tip[1]=0x04;
    arp.arp_tip[2]=0x04;
    arp.arp_tip[3]=0x04;

    memcpy(packet+14, &arp, sizeof(struct arp));

    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, 100 /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
        return -1;
    }

    return 0;
}
