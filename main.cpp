#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#define ETHERTYPE_IP 0x0800

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
} // ��� ���� ��� �Լ�.

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    } // ���� ���� 2�� �ƴϸ� ��� ���� ��� �� ������ ����.

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // ���� ������ ���� ��Ʈ��ũ ��ġ�� ����� promiscuous ���� pcap�� ����.

    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    } // ���� ���ϸ� �޼��� ��� �� ������ ����.

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        // ���� ��Ŷ�� ��� ������ 1�� ��ȯ�Ѵ�.
        if (res == 0) continue; // timeout�� ����� ���(0), �ٽ� ��Ŷ�� ��´�.
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        } // ������(-1), EOF(-2)�� ������ �����Ѵ�.

        struct ether_header *ep;
        struct ip *iph;
        struct tcphdr *tcph;
        // �̴��� ���, IP ���, TCP ��� ����ü�� �����Ѵ�.

        ep = (struct ether_header *)packet;
        // �̴��� ����� ���Ѵ�.
        packet += sizeof(struct ether_header);
        // IP ����� ���ϱ� ���� �̴��� �����ŭ ������.

        if (ntohs(ep->ether_type) == ETHERTYPE_IP){
        iph = (struct ip *)packet;
        // IP ��Ŷ�̸� IP ����� ���Ѵ�.
            if (iph->ip_p == IPPROTO_TCP){
            tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
            // TCP ��Ŷ�̸� TCP ����� ���Ѵ�.

            printf("Src Mac : %s\n",ether_ntoa((struct ether_addr *)ep->ether_shost));
            printf("Dst Mac : %s\n",ether_ntoa((struct ether_addr *)ep->ether_dhost));
            // �̴��� ����� �ִ� Mac �ּҸ� ����Ѵ�. (��ȯ �Լ� ether_ntoa ���)
            printf("Src IP  : %s \n",inet_ntoa(iph->ip_src));
            printf("Dst IP  : %s \n",inet_ntoa(iph->ip_dst));
            // IP ����� �ִ� IP �ּҸ� ����Ѵ�. (��ȯ �Լ� inet_ntoa ���)
            printf("Src Port: %d\n" , ntohs(tcph->th_sport));
            printf("Dst Port: %d\n" , ntohs(tcph->th_dport));
            // TCP ����� �ִ� ��Ʈ�� ����Ѵ�. (��ȯ �Լ� ntohs ���)
            printf("Total Bytes : %u\n", header->caplen);
            // ��Ŷ�� �� ����Ʈ ũ�� ���� ����Ѵ�.

            printf("TCP Payload : "); // TCP ���̷ε带 ����Ѵ�.
            int length = header->len - sizeof (* ep);
            // length�� �� ��Ŷ ũ�� - �̴��� ��� ũ��
            // (IP ��� ũ�� + TCP ��� ũ�� + TCP ���̷ε� ũ��)
            int i=(iph->ip_hl*4)+(tcph->doff*4);
            // i�� IP ��� ũ�� + TCP ��� ũ��
            if (length-i>=16) length=i+16;
            // length-i�� �ϸ� TCP ���̷ε� ���̸� ���� �� ����.
            // TCP ���̷ε� ���̰� 16 �̻��̸� 16���� ����. 
            for(; i<length; i++){
                printf("%02x ", *(packet+i));
            }
            printf("\n\n");
            // TCP ���̷ε� ��� �� ������ ����ش�.
            }
        }
    }
    pcap_close(handle);
    // pcap �ڵ��� �ݾ��ش�.
}