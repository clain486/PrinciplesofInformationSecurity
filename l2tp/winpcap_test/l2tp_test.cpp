#define WIN32
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define MAX_PROTO_TEXT_LEN 16 // 子协议名称最大长度
#define MAX_PROTO_NUM 12      // 子协议数量
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

// 将unsigned long型的IP转换为字符串类型的IP
char* iptos(u_long in) {
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which = 0;
    u_char* p = (u_char*)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);

    // 格式化IP地址字符串
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

// 输出网络接口信息
void print_interface_info(pcap_if_t* device, int num) {
    pcap_addr_t* a;
    printf("\n=================================================\n");
    printf("网卡%d信息：\n", num);
    printf("网卡名      : %s\n", device->name);
    printf("网卡描述    : %s\n", device->description ? device->description : "No description available");
    printf("回环接口    : %s\n", (device->flags & PCAP_IF_LOOPBACK) ? "是" : "否");
    // IP地址
    for (a = device->addresses; a; a = a->next) {
        switch (a->addr->sa_family) {
        case AF_INET:
            printf("IP地址类型  :AF_INET\n");
            if (a->addr)
                printf("IP地址      :%s\n", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
            if (a->netmask)
                printf("掩码        :%s\n", iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr));
            if (a->broadaddr)
                printf("广播地址    :%s\n", iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr));
            if (a->dstaddr)
                printf("目标地址    :%s\n", iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr));
            break;
        default:
            //printf("Address Family Name:Unkown\n");
            break;
        }
    }
}

// 输出UDP协议分析结果
void print_udp_info(udp_header* udpheader) {
    printf("\n=================================================\n");
    printf("UDP协议分析：\n");
    printf("源端口  : %d\n", ntohs(udpheader->sport));
    printf("目的端口: %d\n", ntohs(udpheader->dport));
    printf("数据长度: %d\n", ntohs(udpheader->len));
    printf("校验和  : %d\n", ntohs(udpheader->crc));
}

// 输出IPv4协议分析结果
void print_ipv4_info(ip_header* ipheader) {
    printf("\n=================================================\n");
    printf("IPv4协议分析：\n");
    printf("版本号  : %d\n", (ipheader->ver_ihl & 0xf0) >> 4);
    printf("首部长度: %d bytes\n", (ipheader->ver_ihl & 0xf) * 4);
    printf("服务类型: %d\n", ipheader->tos);
    printf("总长度  : %d bytes\n", ntohs(ipheader->tlen));
    printf("标识    : %d\n", ntohs(ipheader->identification));
    printf("生存时间: %d\n", ipheader->ttl);
    printf("协议    : %s\n", ipheader->proto == IPPROTO_UDP ? "UDP" : "*");
    printf("源地址  :%d.%d.%d.%d\n", ipheader->saddr.byte1, ipheader->saddr.byte2, ipheader->saddr.byte3, ipheader->saddr.byte4);
    printf("目的地址:%d.%d.%d.%d\n", ipheader->daddr.byte1, ipheader->daddr.byte2, ipheader->daddr.byte3, ipheader->daddr.byte4);
}

// 输出以太网协议分析结果
void print_ethernet_info(ethernet_header* ethheader) {
    printf("\n=================================================\n");
    printf("以太网协议分析：\n");
    printf("类型    : %s\n", ntohs(ethheader->type) == 0x0800 ? "IPv4" : "Other");
    printf("源地址  : %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethheader->src_mac_addr.byte1, ethheader->src_mac_addr.byte2, ethheader->src_mac_addr.byte3,
           ethheader->src_mac_addr.byte4, ethheader->src_mac_addr.byte5, ethheader->src_mac_addr.byte6);
    printf("目的地址: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethheader->des_mac_addr.byte1, ethheader->des_mac_addr.byte2, ethheader->des_mac_addr.byte3,
           ethheader->des_mac_addr.byte4, ethheader->des_mac_addr.byte5, ethheader->des_mac_addr.byte6);
}

// 解析L2TP协议
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
    printf("L2TP协议分析：\n");
    printf("0x%x\n", pl2tpheader->tlxxsxop);
    printf("类型            :%s\n", t ? "1(控制信息)" : "0(数据信息)");
    printf("长度在位标志    :%d\n", l);
    printf("顺序字段在位标志:%d\n", s);
    printf("偏移值在位标志  :%d\n", o);
    printf("优先级          :%d\n", pl2tpheader->tlxxsxop & 0x01);
    printf("版本号          :%d\n", pl2tpheader->xxxxver & 0x0f);
    if (l == 1) { // 长度在位标志为1
        printf("消息总长度      :%d\n", ntohs(pl2tpheader->length));
    }
    printf("隧道标识符      :%d\n", ntohs(pl2tpheader->tunnel_id));
    printf("会话标识符      :%d\n", ntohs(pl2tpheader->session_id));
    if (s == 1) { // 顺序字段在位标志为1
        printf("当前消息顺序号  :%d\n", ntohs(pl2tpheader->ns));
        if (t == 1) { // 控制信息nr才有意义
            printf("下一消息顺序号  :%d\n", ntohs(pl2tpheader->nr));
        }
    }
    if (l == 1) { // 偏移值在位标志为1
        printf("偏移量          :%d\n\n", ntohs(pl2tpheader->offset));
    }
    return true;
}

// 解析UDP协议
void decode_udp(char* udpbuf) {
    udp_header* pudpheader = (udp_header*)udpbuf;
    print_udp_info(pudpheader);

    // 判断是否为L2TP协议，如果是则进一步解析
    if (ntohs(pudpheader->sport) == 1701 && ntohs(pudpheader->dport) == 1701) {
        decode_l2tp(udpbuf + sizeof(udp_header));
    }
}

// 解析IPv4协议
void decode_ipv4(char* ipbuf) {
    ip_header* ipheader = (ip_header*)ipbuf;
    print_ipv4_info(ipheader);

    // 如果是UDP协议，则进一步解析
    if (ipheader->proto == IPPROTO_UDP) {
        decode_udp(ipbuf + ((ipheader->ver_ihl & 0xf) * 4)); // 移动到UDP头部的位置
    }
}

// 解析以太网帧
void decode_ethernet(char* etherbuf) {
    ethernet_header* ethheader = (ethernet_header*)etherbuf;
    print_ethernet_info(ethheader);

    // 如果是IPv4协议，则进一步解析
    if (ntohs(ethheader->type) == 0x0800) {
        decode_ipv4(etherbuf + sizeof(ethernet_header));
    }
}

// 包处理回调函数，对于每个嗅探到的数据包
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    // 输出时间戳
    struct tm* ltime;
    char timestr[16];
    time_t local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
    printf("Time: %s.%.6d, Length: %d\n", timestr, header->ts.tv_usec, header->len);
    char mypkt[1000];

    // 打印数据包内容
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

    // 解析以太网帧
    decode_ethernet((char*)pkt_data);
}

int main(int argc, const char* argv[]) {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;

    // 获取本机设备列表
    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    // 打印设备列表，并让用户选择一个接口
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

    // 跳转到已选中的适配器
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    // 打开设备
    pcap_t* adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (adhandle == NULL) {
        fprintf(stderr, "Unable to open the adapter. %s is not supported by WinPcap\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }

    // 检查链接层
    if (pcap_datalink(adhandle) != DLT_EN10MB) {
        fprintf(stderr, "This program works only on Ethernet networks.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    // 获取网络接口的掩码
    if (d->addresses != NULL) {
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    } else {
        netmask = 0xffffff; // 默认C类网络
    }

    // 设置过滤器
    // 筛选出发送的数据(src) 和 到达的数据(dst)
    char packet_filter[] = "src host 47.98.179.198 and src port 1701 and dst port 1701";
    struct bpf_program fcode;
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0 || pcap_setfilter(adhandle, &fcode) < 0) {
        fprintf(stderr, "Error setting the filter.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nListening on %s...\n", d->description);
    pcap_freealldevs(alldevs);

    // 开始嗅探
    pcap_loop(adhandle, 0, packet_handler, NULL);
    pcap_close(adhandle);
    return 0;
}