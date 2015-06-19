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
char dns_server[16];

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

// nome de host para envio simples
unsigned char hostname[HOSTNAMESIZE];

void usage(void){
	fprintf(stderr,
		"Usage: dns-stress [-k | -c COUNT] [-s DNS] [-n FQDN] [-f FILE] [-w]\n"
		"  -c (count): numero de requisicoes a enviar\n"
		"  -s (dns)  : ip de servidor DNS, padrao 127.0.0.1\n"
		"  -f (file) : arquivo com 1 dominio por linha\n"
		"  -p (file) : arquivo com 1 prefixo de dominio (nome de host) por linha\n"
		"  -w        : adicionar www ao nome do dominio\n"
		"  -k        : sufocar servidor, enviar a lista em loop inifito\n"
		"  -n (fqdn) : nome do host, desativa uso da lista\n"
		"  -t (type) : tipo de requisicao: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA,\n"
		"                                  SRV, NAPTR, OPT, TKEY, TSIG, MAILB, ANY\n"
		"  -x        : enviar para o alvo todos os tipos de requisicao\n"
		"\n"
	);
	exit(2);
}


int main (int argc, char **argv) {
	int ch;
	int c;
	int use_hostname = 0; // usar host unico em vez de lista
	int use_prefixes = 0; // usar lista de prefixos
	int rtype = 1; // tipo de registro dns, 1=A
	char rname[10]; strcpy(rname, "a");

	// usar localhost como padrao
	strcpy(dns_server, "127.0.0.1");

	while ((ch = getopt(argc, argv, "p:t:n:c:s:f:wkx")) != EOF) {
		switch(ch) {
		case 'f':
			domainsfile=(optarg); c++;
			break;
		case 'p':
			prefixfile=(optarg); use_prefixes=1;
			break;
		case 'w':
			use_www=1;
			break;
		case 's':
			strncpy(dns_server, optarg, 15);
			dns_server[15] = 0;
			break;
		case 'n':
			strcpy(hostname, optarg);
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

	printf("DNS Stress:\n");
	printf(" Servidor DNS..: %s\n", dns_server);
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
			unsigned char hostname[HOSTNAMESIZE];
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
				strcpy(hostname, globallist[j]);

				// enviar para este dominio
				printf("dns> %s request %d -> [%s]\n", rname, allcount++, hostname);
				dns_presend_request(hostname, rtype);

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
	int i , j , stop , s;

	struct sockaddr_in a;

	struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
	struct sockaddr_in dest;

	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

	s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries

	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	
	dest.sin_addr.s_addr = inet_addr(dns_server); //dns servers

	//Set the DNS structure to standard queries
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

	if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0 ){
		perror("sendto failed");
	}
	
	// fechar
	shutdown(s, 0);
	close(s);
	
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
