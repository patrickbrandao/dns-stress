// DNS Query Stress Program on Linux
// Author : Patrick Brandao (patrickbrandao@gmail.com)
// Dated : 24/06/2014

//Header Files
#include <stdio.h>		//printf
#include <string.h>		//strlen
#include <stdlib.h>		//malloc
#include <sys/socket.h>	//you know what this is for
#include <arpa/inet.h>	//inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>
#include <unistd.h>		//getpid

#include <errno.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/time.h>
#include <math.h>



#define T_ALL       0       // enviar de todo tipo
#define T_A			1		// Ipv4 address
#define T_NS        2    	// Nameserver           
#define T_CNAME		5		// canonical name
#define T_SOA		6		// start of authority zone
#define T_PTR		12		// domain name pointer
#define T_MX		15		// Mail server
#define T_TXT		16		// Txt
#define T_SIG		24
#define T_AAAA		28		// IPv6
#define T_SRV		33
#define T_NAPTR		35
#define T_OPT		41
#define	T_TKEY		249		
#define	T_TSIG		250
#define T_MAILB		253	
#define T_ANY		255

// Function Prototypes
void dns_send_request (unsigned char* , int);
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
void dns_presend_request(unsigned char *host, int query_type);
int ip_check_version(char *addr);

//DNS header structure
struct DNS_HEADER {
	unsigned short id; // identification number
	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag

	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION {
	unsigned short qtype;
	unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD {
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

//Structure of a Query
typedef struct
{
	unsigned char *name;
	struct QUESTION *ques;
} QUERY;

// usar www
int use_www = 0;
int use_scan = 0;

// arquivo com lista de dominios
char *domainsfile;
char *prefixfile;

// nome do servidor dns
char *dns_server;
struct in6_addr ipv6server;
struct in_addr ipv4server;
struct hostent *res_server;

// porta do servidor DNS
int server_port = 0;

// nome de host para envio simples
unsigned char *hostname;

// versao do protocolo ip
int ip_version = 4;			// 4 = ipv4, 6=ipv6

// atacar para sempre
int forever = 0;
// numero de queries a enviar sem forever
int qcount = 0;

// lista de todos os hosts (dominios e hosts)
#define GSIZE 1000000
#define HOSTNAMESIZE 100
char globallist[GSIZE][HOSTNAMESIZE];
int gindex = 0;	// ultimo indice da lista, ponteiro reiniciavel
int gsize = 0;	// numero de elementos na lista global

// lista de todos os prefixos de dominio
#define PSIZE 1000
#define PREFIXSIZE 30
char prefixlist[PSIZE][PREFIXSIZE];
int pindex = 0;	// ultimo indice da lista, ponteiro reiniciavel
int psize = 0;	// numero de elementos na lista global


void usage(void){
	fprintf(stderr,
		"Usage: dns-stress [-k | -c COUNT] [-s DNS] [-n FQDN] [-f FILE] [-w]\n"
		"  -c (count): numero de requisicoes a enviar\n"
		"  -s (dns)  : ip de servidor DNS, padrao 127.0.0.1\n"
		"  -P (port) : porta do servidor dns, padrao 53\n"
		"  -f (file) : arquivo com 1 dominio por linha\n"
		"  -p (file) : arquivo com 1 prefixo de dominio (nome de host) por linha\n"
		"  -w        : adicionar www ao nome do dominio\n"
		"  -k        : sufocar servidor, enviar a lista em loop inifito\n"
		"  -4        : usar IPv4 (padrao)\n"
		"  -6        : usar IPv6\n"
		"  -n (fqdn) : nome do host, desativa uso da lista\n"
		"  -t (type) : tipo de requisicao: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA,\n"
		"                                  SRV, NAPTR, OPT, TKEY, TSIG, MAILB, ANY\n"
		"  -x        : enviar para o alvo todos os tipos de requisicao\n"
		"\n"
	);
	exit(2);
}


int main (int argc, char **argv) {
	char tmpstr[INET6_ADDRSTRLEN];

	int ch;
	int c;
	int use_hostname = 0; // usar host unico em vez de lista
	int use_prefixes = 0; // usar lista de prefixos
	int rtype = 1; // tipo de registro dns, 1=A
	char rname[10]; strcpy(rname, "a");

	//bzero(dns_server, INET6_ADDRSTRLEN);
	//bzero(hostname, HOSTNAMESIZE);

	// strcpy(dns_server, "127.0.0.1");

	while ((ch = getopt(argc, argv, "46p:P:t:n:c:s:f:wkx")) != EOF) {
		switch(ch) {
		case 'f':
			domainsfile=(optarg); c++;
			break;
		case '4': ip_version = 4; break;
		case '6': ip_version = 6; break;

		case 'P': server_port = atoi(optarg); break;

		case 'p':
			prefixfile=(optarg); use_prefixes=1;
			break;
		case 'w':
			use_www=1;
			break;
		case 's':
			dns_server = (char*)optarg;
			//strncpy(dns_server, optarg, strlen(optarg) );
			// dns_server[15] = 0;
			break;
		case 'n':
			hostname = (char*)optarg;
			//strncpy(hostname, optarg, strlen(optarg) );
			// strcpy(hostname, optarg);
			use_hostname = 1;
			break;
		case 'c':
			qcount = atoi(optarg);
			break;
		case 't':
			strncpy(rname, optarg, 9);
			rname[9] = 0;
			break;
		case 'k':
			forever = 1;
			break;
		case 'x':
			use_scan = 1;
			strcpy(rname, "all");
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}
	if(!use_hostname && !domainsfile){ fprintf(stderr, "Erro: arquivo de dominio nao informado\n"); usage(); }
	if(!dns_server){ fprintf(stderr, "Erro: servidor dns invalido\n"); usage(); }
	if(use_hostname && !hostname){ fprintf(stderr, "Erro: nome de host fqdn invalido\n"); usage(); }
	if(qcount && forever){ fprintf(stderr, "Erro: escolha entre -k ou -c\n"); usage(); }

	if(!server_port || server_port > 65535) server_port = 53;

	// caso o usuario especifique o ip do servidor DNS, ajustar para o numero do protocolo IP utilizado
	c = ip_check_version(dns_server);
	if(c) ip_version = c;
	
	
	// resolver nome, caso usuario tenha informado nome do servidor DNS
	if(ip_version==6){
		// obter ipv6
		res_server = gethostbyname2(dns_server, AF_INET6);
	}else{
		// obter ipv4
		res_server = gethostbyname(dns_server);
	}

	// problemas na resolucao de nomes
	if( (res_server) == NULL){
		fprintf(stderr,"error=resolv problem\n");
		exit(2);
	}

	// extrair endereco IP binario da resolucao de DNS
	if(ip_version==6){
		// Obter ipv6 (128bits)
		ipv6server = *((struct in6_addr *)res_server->h_addr);

		inet_ntop(AF_INET6, *res_server->h_addr_list, tmpstr, sizeof(tmpstr));
		printf("dns-stress server=%s address=%s port=%d\n", dns_server, tmpstr, server_port);
	
	}else{
		// Obter ipv4 (32bits)
		ipv4server = *((struct in_addr *)res_server->h_addr);

		inet_ntop(AF_INET, *res_server->h_addr_list, tmpstr, sizeof(tmpstr));
		printf("dns-stress server=%s address=%s port=%d\n", dns_server, tmpstr, server_port);
	}


	// ajustar tipo
	if(rname){
		for(c = 0; rname[c] && c < 10; c++) rname[c] = toupper(rname[c]);
		if(strcmp(rname, "ALL")==0){ rtype = T_ALL; use_scan = 1; use_www = 0; }
		if(strcmp(rname, "A")==0) rtype = T_A;
		if(strcmp(rname, "NS")==0) rtype = T_NS;
		if(strcmp(rname, "CNAME")==0) rtype = T_CNAME;
		if(strcmp(rname, "SOA")==0) rtype = T_SOA;
		if(strcmp(rname, "PTR")==0) rtype = T_PTR;
		if(strcmp(rname, "MX")==0) rtype = T_MX;
		if(strcmp(rname, "TXT")==0) rtype = T_TXT;
		if(strcmp(rname, "SIG")==0) rtype = T_SIG;
		if(strcmp(rname, "AAAA")==0) rtype = T_AAAA;

		if(strcmp(rname, "SRV")==0) rtype = T_SRV;
		if(strcmp(rname, "NAPTR")==0) rtype = T_NAPTR;
		if(strcmp(rname, "OPT")==0) rtype = T_OPT;
		if(strcmp(rname, "TKEY")==0) rtype = T_TKEY;
		if(strcmp(rname, "TSIG")==0) rtype = T_TSIG;
		if(strcmp(rname, "MAILB")==0) rtype = T_MAILB;

		if(strcmp(rname, "ANY")==0) rtype = T_ANY;

	}
	if(rtype!=1) use_www = 0;

//	printf("DNS Stress:\n");
//	printf(" Servidor DNS..: %s - %s\n", dns_server, (ip_version==6?"IPv6":"IPv4"));
	if(!use_scan)
		printf(" Tipo..........: %s (%d)\n", rname, rtype);
	else
		printf(" Tipo..........: TODOS\n");

	if(qcount){
		printf(" Requisicoes...: %d\n", qcount);
	}else{
		printf(" Infinito......: %s\n", forever?"Sim":"Nao");
	}
	if(!use_hostname){
		printf(" Arquivo.......: %s\n", domainsfile);
		printf(" Adicionar www : %s\n", use_www?"Sim":"Nao");
	}else{
		printf(" Hostname......: %s\n", hostname);
	}

	// carregar lista de prefixos
	if(use_prefixes){

		int i;
		int j;
		int pi = 0;
		FILE *fx;
		char line[200] , *p;
		if((fx = fopen(prefixfile , "r")) == NULL){
			fprintf(stderr, "Falha ao abrir arquivo com prefixos de dominios\n");
			usage();
		}
		// ler dominios
		while(fgets(line , 200 , fx)){
			int l = 0;
			char c;
	
			if(line[0] == '#' || line[0] == ' ' || line[0]==(char)10) continue;
			l = strlen(line);
	
			while(--l && line[l]==(char)10) line[l] = 0;
			if(!l) continue;
			
			// primeiro host
			i = 0;
			strcpy(prefixlist[pindex++], line);
			printf("prefix> %s\n", line);
			
			// limite atingido
			if(pindex >= PSIZE) break;
			
		}
		fclose(fx);
		if(!pindex){
			fprintf(stderr, "prefix> Nenhum prefixo encontrado no arquivo\n");
			use_prefixes = 0;
		}else{
			use_www = 0;
			printf("prefix> total: %d prefixos\n", pindex);
		}
	}

	// enviar requisicao por host fixo , A record
	if(use_hostname){
		int pidx = 0;
		c=0;
		while(forever || qcount-- > 0){
			unsigned char xhostname[HOSTNAMESIZE];
			strcpy(xhostname, hostname);

			if(use_prefixes){
				// requisicao para lista de prefixos
				sprintf(xhostname, "%s.%s", prefixlist[pidx], hostname);

				// requisicao para nome concatenado
				printf("dns> %s request %d -> [%s]\n", rname, ++c, xhostname);

				pidx++;
				if(pidx>=pindex) pidx = 0;
			}else{
			
				// requisicao para nome digitado
				printf("dns> %s request %d -> [%s]\n", rname, ++c, xhostname);
			}
			dns_presend_request(xhostname , rtype);
		}
		return 0;
	}


	// carregar arquivo linha a linha
	if(!use_hostname){
		int i;
		int j;
		int allcount = 0;
		int gi = 0;
		FILE *fp;
		char line[200] , *p;
		if((fp = fopen(domainsfile , "r")) == NULL){
			fprintf(stderr, "Falha ao abrir arquivo com lista de dominios\n");
			usage();
		}
		// ler dominios
		while(fgets(line , 200 , fp)){
			int l = 0;
			char c;
	
			if(line[0] == '#' || line[0] == ' ' || line[0]==(char)10) continue;
			l = strlen(line);
	
			while(--l && line[l]==(char)10) line[l] = 0;
			if(!l) continue;
			
			// primeiro host
			i = 0;
			strcpy(globallist[gindex++], line);
			
			if(use_www){
				i++;
				strcpy(globallist[gindex], "www.");
				l = strlen(line);
				for(j=4; j<l+4; j++) globallist[gindex][j] = line[j-4];
				gindex++;
			}
			
			// limite atingido
			if(gindex >= GSIZE) break;
			
		}
		fclose(fp);
		if(!gindex){
			fprintf(stderr, "Nenhum dominio encontrado no arquivo\n");
		}

		// processar lista global e enviar requisicoes	
		printf("Iniciando envio\n");
		printf("Lista de hosts: %d\n", gindex);
		gi = gindex;
		j = 0;
		

		// loop infinito por padrao
		while(1){
			unsigned char _hostname[HOSTNAMESIZE];
			unsigned char xprefixhostname[HOSTNAMESIZE];			
			
			if(use_prefixes){

				int pidx = 0;
				
				// enviar para todos os prefixos nesse dominio
				for(pidx = 0; pidx < pindex; pidx++){

	
					// requisicao para lista de prefixos
					sprintf(xprefixhostname, "%s.%s", prefixlist[pidx], globallist[j]);
	
					// requisicao para nome concatenado
					printf("dns> %s request %d -> [%s]\n", rname, allcount++, xprefixhostname);
					dns_presend_request(xprefixhostname, rtype);

					// modo contagem de requisicoes
					if(qcount && !--qcount) return 0;

				}

			}else{
				strcpy(_hostname, globallist[j]);
				//hostname = strdup((char *)globallist[j]);

				// enviar para este dominio
				printf("dns> %s request %d -> [%s]\n", rname, allcount++, _hostname);
				dns_presend_request(_hostname, rtype);

			}

			
		
			
			
			// deslocamento do indice
			j++;
			if(j >= gindex) j = 0;

			if(!forever && !qcount) if(!--gi) return 0;

			// modo contagem de requisicoes
			if(qcount && !--qcount) return 0;

		}


		return 0;
	}


	return 0;
}

// verificar versao do endereco informado
int ip_check_version(char *addr){
	int c, ipv = 0; // 0 = desconhecido, 4=ipv4, 6=ipv6
	
	int slen = 0;
	int found_dot = 0;
	int found_colon = 0;
	int found_num = 0;
	int found_hex = 0;

	slen = strlen(addr);
	
	// string vazia nao e' ip
	if(!slen) return ipv;
	
	// percorrer byte a byte e coletar caracteres encontrados pelo tipo-familia
	for(c=0; c < slen; c++){
		char at = addr[c];
		
		// A-F a-f
		//97 a 102
		//65 a 70
		if( (at >= 97 && at <= 102) || (at >= 97 && at <= 102) ){
			// printf("FOUND HEX\n");
			found_hex = 1;
			continue;
		}
		
		// 0-9
		if(at >= 48 && at <= 57){
			//printf("FOUND HEX/NUM\n");
			found_num = 1;
			found_hex = 1;
			continue;
		}
		
		// :
		if(at==':'){
			// printf("FOUND COLON\n");
			found_colon = 1;
			continue;
		}

		// .
		if(at=='.'){
			// printf("FOUND DOT\n");
			found_dot = 1;
			continue;
		}
	
		// acabou
		if(!at) break;

		// desconhecido para o formato ip4 e ip6
		// printf("UNKNOW: [%c] [%d]\n", at, at);
		return ipv;
	}
	
	// detectar coerencia
	if( (found_num && found_dot) && ! (found_colon || found_hex) ) ipv = 4;
	if( ( found_hex && found_colon) && !found_dot ) ipv = 6;
	
	return ipv;
}


// Preparar chamada de requisicao por tipo
void dns_presend_request(unsigned char *host, int query_type){
	
	if(!query_type){
		unsigned char tmp[HOSTNAMESIZE];
		int slen = 0;
		strcpy(tmp, host);
		slen = strlen(tmp);
		
		// enviar de todo tipo
		printf("   > A\n");		dns_send_request(tmp , T_A);		tmp[slen] = 0;
		printf("   > NS\n");	dns_send_request(tmp , T_NS);		tmp[slen] = 0;

		printf("   > CNAME\n");	dns_send_request(tmp , T_CNAME);	tmp[slen] = 0;
		printf("   > SOA\n");	dns_send_request(tmp , T_SOA);		tmp[slen] = 0;
		printf("   > PTR\n");	dns_send_request(tmp , T_PTR);		tmp[slen] = 0;
		printf("   > MX\n");	dns_send_request(tmp , T_MX);		tmp[slen] = 0;
		printf("   > TXT\n");	dns_send_request(tmp , T_TXT);		tmp[slen] = 0;
		printf("   > SIG\n");	dns_send_request(tmp , T_SIG);		tmp[slen] = 0;
		printf("   > AAAA\n");	dns_send_request(tmp , T_AAAA);		tmp[slen] = 0;
		printf("   > SRV\n");	dns_send_request(tmp , T_SRV);		tmp[slen] = 0;
		printf("   > NAPTR\n");	dns_send_request(tmp , T_NAPTR);	tmp[slen] = 0;
		printf("   > OPT\n");	dns_send_request(tmp , T_OPT);		tmp[slen] = 0;
		printf("   > TKEY\n");	dns_send_request(tmp , T_TKEY);		tmp[slen] = 0;
		printf("   > TSIG\n");	dns_send_request(tmp , T_TSIG);		tmp[slen] = 0;
		printf("   > MAILB\n");	dns_send_request(tmp , T_MAILB);	tmp[slen] = 0;
		printf("   > ANY\n");	dns_send_request(tmp , T_ANY);		tmp[slen] = 0;

	}else{
		// apenas tipo solicitado
		dns_send_request(host , query_type);
	}
	
}


// Perform a DNS query by sending a packet
void dns_send_request(unsigned char *host , int query_type){
	unsigned char buf[65536],*qname,*reader;
	int i , j , stop , sockfd;

	struct sockaddr_in a;

	struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server

	struct sockaddr_in dest4;
	struct sockaddr_in6 dest6;

	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

	if(ip_version==6){
	
		// Criar socket ipv6
		sockfd = socket(AF_INET6, SOCK_DGRAM , IPPROTO_UDP);
		if (sockfd < 0){
			fprintf(stderr,"error=socket problem ipv6\n");
			exit(1);
		}

		// IPv6	
		memset((char *) &dest6, 0, sizeof(dest6));
		dest6.sin6_flowinfo = 0;
		dest6.sin6_family = AF_INET6;
		dest6.sin6_addr = ipv6server;
		dest6.sin6_port = htons(server_port);

	}else{

		// Criar socket ipv4
		sockfd = socket(AF_INET, SOCK_DGRAM , IPPROTO_UDP);
		if (sockfd < 0){
			fprintf(stderr,"error=socket problem ipv4\n");
			exit(1);
		}

		// IPv4
		memset((char *) &dest4, 0, sizeof(dest4));

		dest4.sin_family = AF_INET;
		dest4.sin_port = htons(server_port);
		dest4.sin_addr = ipv4server;

	}

	// Set the DNS structure to standard queries
	dns = (struct DNS_HEADER *)&buf;

	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; 		//This is a query
	dns->opcode = 0; 	//This is a standard query
	dns->aa = 0; 		//Not Authoritative
	dns->tc = 0; 		//This message is not truncated
	dns->rd = 1; 		//Recursion Desired
	dns->ra = 0; 		//Recursion not available! hey we dont have it (lol)
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;

	//point to the query portion
	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

	ChangetoDnsNameFormat(qname , host);
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

	qinfo->qtype = htons( query_type );		// type of the query , A , MX , CNAME , NS etc
	qinfo->qclass = htons(1);				// its internet (lol)

	// Enviar datagrama
	if(ip_version == 6){

		// Enviar em IPv6
		if( sendto(
				sockfd,
				(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),
				0,
				(struct sockaddr*)&dest6,
				sizeof(dest6)
			) < 0 ){
			perror("sendto failed ipv6");
		}

	}else{
		
		// Enviar em IPv4
		if( sendto(
				sockfd,
				(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),
				0,
				(struct sockaddr*)&dest4,
				sizeof(dest4)
			) < 0 ){
			perror("sendto failed ipv4");
		}

	}

	
	// fechar
	shutdown(sockfd, 0);
	close(sockfd);
	
	return;
}

/*
 * This will convert www.google.com to 3www6google3com 
 * got it :)
 * */
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host){
	int lock = 0 , i;
	strcat((char*)host,".");
	
	for(i = 0 ; i < strlen((char*)host) ; i++) 
	{
		if(host[i]=='.') 
		{
			*dns++ = i-lock;
			for(;lock<i;lock++) 
			{
				*dns++=host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++='\0';
}
