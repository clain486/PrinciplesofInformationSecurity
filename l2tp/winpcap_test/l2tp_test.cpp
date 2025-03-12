#define WIN32
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define MAX_PROTO_TEXT_LEN 16 // ��Э��������󳤶�
#define MAX_PROTO_NUM 12      // ��Э������
#define IPSEC_PORT 4500
#define L2TP_PORT 1701
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
using namespace std;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "l2tp_test.h"

char a[15] = "Hello-World-TJ";

#define IPTOSBUFFERS 12

// ��unsigned long�͵�IPת��Ϊ�ַ������͵�IP
char* iptos(u_long in) {
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which = 0;
    u_char* p = (u_char*)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);

    // ��ʽ��IP��ַ�ַ���
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

// �������ӿ���Ϣ
void print_interface_info(pcap_if_t* device, int num) {
    pcap_addr_t* a;
    printf("\n=================================================\n");
    printf("����%d��Ϣ��\n", num);
    printf("������      : %s\n", device->name);
    printf("��������    : %s\n", device->description ? device->description : "No description available");
    printf("�ػ��ӿ�    : %s\n", (device->flags & PCAP_IF_LOOPBACK) ? "��" : "��");
    // IP��ַ
    for (a = device->addresses; a; a = a->next) {
        switch (a->addr->sa_family) {
        case AF_INET:
            printf("IP��ַ����  :AF_INET\n");
            if (a->addr)
                printf("IP��ַ      :%s\n", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
            if (a->netmask)
                printf("����        :%s\n", iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr));
            if (a->broadaddr)
                printf("�㲥��ַ    :%s\n", iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr));
            if (a->dstaddr)
                printf("Ŀ���ַ    :%s\n", iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr));
            break;
        default:
            //printf("Address Family Name:Unkown\n");
            break;
        }
    }
}

// ���UDPЭ��������
void print_udp_info(udp_header* udpheader) {
    printf("\n=================================================\n");
    printf("UDPЭ�������\n");
    printf("Դ�˿�  : %d\n", ntohs(udpheader->sport));
    printf("Ŀ�Ķ˿�: %d\n", ntohs(udpheader->dport));
    printf("���ݳ���: %d\n", ntohs(udpheader->len));
    printf("У���  : %d\n", ntohs(udpheader->crc));
}

// ���IPv4Э��������
void print_ipv4_info(ip_header* ipheader) {
    printf("\n=================================================\n");
    printf("IPv4Э�������\n");
    printf("�汾��  : %d\n", (ipheader->ver_ihl & 0xf0) >> 4);
    printf("�ײ�����: %d bytes\n", (ipheader->ver_ihl & 0xf) * 4);
    printf("��������: %d\n", ipheader->tos);
    printf("�ܳ���  : %d bytes\n", ntohs(ipheader->tlen));
    printf("��ʶ    : %d\n", ntohs(ipheader->identification));
    printf("����ʱ��: %d\n", ipheader->ttl);
    printf("Э��    : %s\n", ipheader->proto == IPPROTO_UDP ? "UDP" : "*");
    printf("Դ��ַ  :%d.%d.%d.%d\n", ipheader->saddr.byte1, ipheader->saddr.byte2, ipheader->saddr.byte3, ipheader->saddr.byte4);
    printf("Ŀ�ĵ�ַ:%d.%d.%d.%d\n", ipheader->daddr.byte1, ipheader->daddr.byte2, ipheader->daddr.byte3, ipheader->daddr.byte4);
}

// �����̫��Э��������
void print_ethernet_info(ethernet_header* ethheader) {
    printf("\n=================================================\n");
    printf("��̫��Э�������\n");
    printf("����    : %s\n", ntohs(ethheader->type) == 0x0800 ? "IPv4" : "Other");
    printf("Դ��ַ  : %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethheader->src_mac_addr.byte1, ethheader->src_mac_addr.byte2, ethheader->src_mac_addr.byte3,
           ethheader->src_mac_addr.byte4, ethheader->src_mac_addr.byte5, ethheader->src_mac_addr.byte6);
    printf("Ŀ�ĵ�ַ: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethheader->des_mac_addr.byte1, ethheader->des_mac_addr.byte2, ethheader->des_mac_addr.byte3,
           ethheader->des_mac_addr.byte4, ethheader->des_mac_addr.byte5, ethheader->des_mac_addr.byte6);
}

// ����L2TPЭ��
int decode_l2tp(char* l2tpbuf)
{
    struct l2tp_header* pl2tpheader;
    pl2tpheader = (l2tp_header*)l2tpbuf;
    u_short t, l, s, o;
    t = (pl2tpheader->tlxxsxop & 0x80) >> 7;
    l = (pl2tpheader->tlxxsxop & 0x40) >> 6;
    s = (pl2tpheader->tlxxsxop & 0x08) >> 3;
    o = (pl2tpheader->tlxxsxop & 0x02) >> 1;

    printf("\n=================================================\n");
    printf("L2TPЭ�������\n");
    printf("0x%x\n", pl2tpheader->tlxxsxop);
    printf("����            :%s\n", t ? "1(������Ϣ)" : "0(������Ϣ)");
    printf("������λ��־    :%d\n", l);
    printf("˳���ֶ���λ��־:%d\n", s);
    printf("ƫ��ֵ��λ��־  :%d\n", o);
    printf("���ȼ�          :%d\n", pl2tpheader->tlxxsxop & 0x01);
    printf("�汾��          :%d\n", pl2tpheader->xxxxver & 0x0f);
    if (l == 1) { // ������λ��־Ϊ1
        printf("��Ϣ�ܳ���      :%d\n", ntohs(pl2tpheader->length));
    }
    printf("�����ʶ��      :%d\n", ntohs(pl2tpheader->tunnel_id));
    printf("�Ự��ʶ��      :%d\n", ntohs(pl2tpheader->session_id));
    if (s == 1) { // ˳���ֶ���λ��־Ϊ1
        printf("��ǰ��Ϣ˳���  :%d\n", ntohs(pl2tpheader->ns));
        if (t == 1) { // ������Ϣnr��������
            printf("��һ��Ϣ˳���  :%d\n", ntohs(pl2tpheader->nr));
        }
    }
    if (l == 1) { // ƫ��ֵ��λ��־Ϊ1
        printf("ƫ����          :%d\n\n", ntohs(pl2tpheader->offset));
    }
    return true;
}

// ����UDPЭ��
void decode_udp(char* udpbuf) {
    udp_header* pudpheader = (udp_header*)udpbuf;
    print_udp_info(pudpheader);

    // �ж��Ƿ�ΪL2TPЭ�飬��������һ������
    if (ntohs(pudpheader->sport) == 1701 && ntohs(pudpheader->dport) == 1701) {
        decode_l2tp(udpbuf + sizeof(udp_header));
    }
}

// ����IPv4Э��
void decode_ipv4(char* ipbuf) {
    ip_header* ipheader = (ip_header*)ipbuf;
    print_ipv4_info(ipheader);

    // �����UDPЭ�飬���һ������
    if (ipheader->proto == IPPROTO_UDP) {
        decode_udp(ipbuf + ((ipheader->ver_ihl & 0xf) * 4)); // �ƶ���UDPͷ����λ��
    }
}

// ������̫��֡
void decode_ethernet(char* etherbuf) {
    ethernet_header* ethheader = (ethernet_header*)etherbuf;
    print_ethernet_info(ethheader);

    // �����IPv4Э�飬���һ������
    if (ntohs(ethheader->type) == 0x0800) {
        decode_ipv4(etherbuf + sizeof(ethernet_header));
    }
}

// ������ص�����������ÿ����̽�������ݰ�
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    // ���ʱ���
    struct tm* ltime;
    char timestr[16];
    time_t local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
    printf("Time: %s.%.6d, Length: %d\n", timestr, header->ts.tv_usec, header->len);
    char mypkt[1000];

    // ��ӡ���ݰ�����
    int len = header->caplen;
    for (int i = 0; i < len; i++) {
        if(i<=93)
            mypkt[i] = pkt_data[i];
        printf("%.2x ", pkt_data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    printf("\n-------------------------------------------------\n");

    for (int i = 1; i < len; i++)
    {
        char temp = mypkt[i - 1];
        if (temp >= 32 && temp <= 126) {
            printf("%c", temp);
        }
        else {
            printf(".");
        }
        if ((i % 16) == 0)
            printf("\n");
    }
    printf("\n-------------------------------------------------\n");

    for (int i = 93; i < 93 + 15; i++) {
        mypkt[i - 1] = a[i - 93];
    }

    for (int i = 1; i < 93 + 15; i++)
    {
        if (i == 93)
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE);
        char temp = mypkt[i - 1];
        if (temp >= 32 && temp <= 126) {
            printf("%c", temp);
        }
        else {
            printf(".");
        }
        if ((i % 16) == 0)
            printf("\n");
    }
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);

    decode_ethernet((char*)pkt_data);

    printf("\n-------------------------------------------------\n");
    printf("\n\n");

    // ������̫��֡
    decode_ethernet((char*)pkt_data);
}

int main(int argc, const char* argv[]) {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;

    // ��ȡ�����豸�б�
    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    // ��ӡ�豸�б������û�ѡ��һ���ӿ�
    int i = 0;
    for (d = alldevs, i = 0; d; d = d->next, i++) {
        print_interface_info(d, i + 1);
    }
    if (i == 0) {
        printf("No interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d): ", i);
    scanf("%d", &inum);

    if (inum < 1 || inum > i) {
        printf("Interface number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    // ��ת����ѡ�е�������
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    // ���豸
    pcap_t* adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (adhandle == NULL) {
        fprintf(stderr, "Unable to open the adapter. %s is not supported by WinPcap\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }

    // ������Ӳ�
    if (pcap_datalink(adhandle) != DLT_EN10MB) {
        fprintf(stderr, "This program works only on Ethernet networks.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    // ��ȡ����ӿڵ�����
    if (d->addresses != NULL) {
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    } else {
        netmask = 0xffffff; // Ĭ��C������
    }

    // ���ù�����
    // ɸѡ�����͵�����(src) �� ���������(dst)
    char packet_filter[] = "src host 47.98.179.198 and src port 1701 and dst port 1701";
    struct bpf_program fcode;
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0 || pcap_setfilter(adhandle, &fcode) < 0) {
        fprintf(stderr, "Error setting the filter.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nListening on %s...\n", d->description);
    pcap_freealldevs(alldevs);

    // ��ʼ��̽
    pcap_loop(adhandle, 0, packet_handler, NULL);
    pcap_close(adhandle);
    return 0;
}