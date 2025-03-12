#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define MAX_PROTO_TEXT_LEN 16 // ��Э��������󳤶�
#define MAX_PROTO_NUM 12      // ��Э������

// ����mac��ַ��ʽ
typedef struct mac_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
}mac_address;

// ������̫���ײ���ʽ
typedef struct ethernet_header
{
    mac_address des_mac_addr;
    mac_address src_mac_addr;
    u_short type;
}ethernet_header;

// ����IPv4��ַ�ṹ
typedef struct ipv4_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

// ����IP�ײ���ʽ
typedef struct ipv4_header
{
    u_char ver_ihl;         // �汾���ײ�����
    u_char tos;             // ��������
    u_short tlen;           // �ܳ���
    u_short identification; // ��ʶ��
    u_short flags_fo;       // ��ƫ����
    u_char ttl;             // ����ʱ��
    u_char proto;           // Э��
    u_short crc;            // �ײ�У���
    ipv4_address saddr;     // Դip��ַ
    ipv4_address daddr;     // Ŀ�ĵ�ַ
    u_int op_pad;           // ѡ����λ
}ip_header;

// ����UDP�ײ���ʽ
typedef struct udp_header
{
    u_short sport; // 16bitԴ�˿�
    u_short dport; // 16bitĿ�Ķ˿�
    u_short len;   // 16bit����
    u_short crc;   // 16bit У���
}udp_header;

// ����l2tp�ײ���ʽ
typedef struct l2tp_header
{
    u_char tlxxsxop;       // t���ͣ�0����1���ƣ� 
    // l������λ��־�����Ʊ�Ϊ1�� 
    // s˳���ֶ���λ��־��1����ns nr���Ʊ�Ϊ1��
    // oƫ��ֵ��λ��־
    // p���ȼ�������������Ϣ ���Ʊ�Ϊ0��
    u_char xxxxver;        // �汾��
    u_short length;        // ��Ϣ�ܳ���
    u_short tunnel_id;     // �����ʶ�� ��������
    u_short session_id;    // �Ự��ʶ�� ��������
    u_short ns;            // ��ǰ��Ϣ˳���
    u_short nr;            // ��һ������Ϣ˳��ţ�������ϢΪ�����ֶ�
    u_short offset;        // ƫ��ֵ ָʾ�غɿ�ʼλ��
    u_short offser_pading; // ƫ�������

}l2tp_header;