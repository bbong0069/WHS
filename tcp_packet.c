#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

//패킷 캡쳐하는 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet){
  struct ethheader *eth = (struct ethheader *)packet; //매개변수로 받은 패킷

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
		//ip헤더 구조체를 선언한다. ip헤더는 이더넷 헤더 뒤에 나타나기 때문에 이더넷 헤더 이후를 가리키게 함
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));  
    int ip_header_len = ip->iph_ihl * 4; //iph_ihl 필드는 32비트 워드. -> 바이트 단위로 계산하기 위해 *4
    
    if(ip->iph_protocol==IPPROTO_TCP){//TCP 타입만 받아 출력할 것 -> TCP 외는 무시
				//TCP 구조체 선언, ip 헤더 이후에 tcp헤더 시작                   
        struct tcpheader *tcp=(struct tcpheader*)((u_char*)ip + ip_header_len);

				//Etherent
				//송수신하는 MAC 주소를 출력한다.
        printf("       Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("  Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
                
        //IP
				//inet_ntoa = 32비트 IPv4주소를 문자열 형태로 변환
				//송수신 하는 IP 주소 출력
        printf("	Soruce IP: %s\n",inet_ntoa(ip->iph_sourceip));
				printf("   Destination IP: %s\n",inet_ntoa(ip->iph_destip));
	
        //TCP
				//ntohs = 네트워크 바이트 순서로 저장된 16비트 정수를 호스트 바이트 순서로 변환
				//송수신하는 TCP 포트 출력
				printf("      Soruce Port: %d\n",ntohs(tcp->tcp_sport));
				printf(" Destination Port: %d\n",ntohs(tcp->tcp_dport));
	
				//TCP Message
				//TCP 데이터(메시지)의 시작 위치를 나타낸다.
				int tcp_data_position = ntohs(ip->iph_len) - ip_header_len - (TH_OFF(tcp)*4);

				//만약 데이터(메세지)가 존재하지 않다면 No Message를 출력한다
				if(tcp_data_position<=0)
				    printf("       No Message: \n");
				else{
				    printf("      TCP Message: ");
				    for(int i=0;i<100;i++) //적당한 길이로 출력하기 위해 100을 넣어줬다. 
				        printf("%c",packet[tcp_data_position+i]); //데이터의 위치부터 메시지를 출력한다.
				    printf("\n");
				}
				printf("\n");
	
    }

  }
}


int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name e3
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
