/*
 * Copyright (C) 2015 Patrick Brandao <patrickbrandao@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <syslog.h>
#include <errno.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>


#include "tcp-crossover.h"

struct struct_cross CrossOver;
int pidFilehandle;

static struct option options_table[] = {
	{ "local",     required_argument, NULL, LOCAL_OPTION },
	{ "remote",    required_argument, NULL, REMOTE_OPTION },
	{ "bs",        required_argument, NULL, BUFFER_SIZE_OPTION },
	{ "pidfile",   required_argument, NULL, PIDFILE_OPTION },
	{ "debug",     no_argument,       NULL, DEBUG_OPTION },
	{ "help",      no_argument,       NULL, HELP_OPTION },
	{ "version",   no_argument,       NULL, VERSION_OPTION },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[]){
	int xpid;

	// limpar lixo de memoria
	memset(&CrossOver, 0, sizeof(CrossOver));

	// carregar opcoes dos parametros
	load_argv_config(argc, argv);


	// debug de opcoes de entrada
	if(CrossOver.debug>1) print_crossover(&CrossOver);

	// abrir porta para receber conexoes
	if (build_server() == 1) exit(1);

	// DEBUG
	if(CrossOver.debug>2){
		server_start();
		return 0;
	}

	// Fazer FORK
	xpid=fork();
	if(xpid==-1){
		perror("Fork error") ;
		exit(-1) ;
	}else if(xpid==0){
		// Processo filho
		// Iniciar servidor

		// Que os jogos comecem:
		server_start();

    }else{
		// Processo Pai, abandona-lo
		exit(0);
	}

	// pronto!
	return 0;
}

// Iniciar escuta por clientes
void server_start(){
	char pidstr[10];

	int j=0;

	setlogmask(LOG_UPTO(LOG_INFO));
	openlog (DAEMON_NAME, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
	//openlog(DAEMON_NAME, LOG_CONS | LOG_PERROR, LOG_USER); 
	syslog(LOG_INFO, "TCP-Cross64 starting up");

	syslog(LOG_INFO, "TCP-Cross64 running");

	// Gravar PidFile
	if(CrossOver.pidfile){
		pidFilehandle = open(CrossOver.pidfile, O_RDWR|O_CREAT, 0600);
		if (pidFilehandle == -1 ) {
			fprintf(stderr, "Could not open PID lock file %s, exiting", CrossOver.pidfile);
			abort_failure("PidFile open error");
		}
		// Travar arquivo, impedir uso concorrente
		if (lockf(pidFilehandle,F_TLOCK,0) == -1){
			fprintf(stderr, "Could not lock PID lock file %s, exiting", CrossOver.pidfile);
			abort_failure("PidFile lock error");
		}	
		// Obter pid na string
		sprintf(pidstr,"%d\n",getpid());
		
		// gravar no arquivo
		write(pidFilehandle, pidstr, strlen(pidstr));
	}
	
	// Capturar sinais
	struct sigaction newSigAction;
	sigset_t createSigSet;
	sigemptyset(&createSigSet);
	sigaddset(&createSigSet, SIGCHLD);
	sigaddset(&createSigSet, SIGTSTP);
	sigaddset(&createSigSet, SIGTTOU);
	sigaddset(&createSigSet, SIGTTIN);
	sigprocmask(SIG_BLOCK, &createSigSet, NULL);
	
	/* Set up a signal handler */
	newSigAction.sa_handler = signal_handler;
	sigemptyset(&newSigAction.sa_mask);
	newSigAction.sa_flags = 0;

	/* Signals to handle */
	sigaction(SIGHUP, &newSigAction, NULL);     /* catch hangup signal */
	sigaction(SIGTERM, &newSigAction, NULL);    /* catch term signal */
	sigaction(SIGINT, &newSigAction, NULL);     /* catch interrupt signal */

	// Previnir defuntos
	signal(SIGCHLD, SIG_IGN);


	// processar conexoes
	do {
		if (wait_for_clients() == 0) handle_client();
		j++;
		if(j>10) break;
	} while (1);

	// fechar servidor
	close(CrossOver.server_socket);
}

// Processamento de sinais
void signal_handler(int sig){
	switch(sig){
		case SIGHUP:
			syslog(LOG_WARNING, "Received SIGHUP signal.");
			break;
	
		case SIGINT:
		case SIGTERM:
			syslog(LOG_INFO, "Daemon exiting");
			daemonShutdown();
			exit(EXIT_SUCCESS);
			break;
	
		default:
			syslog(LOG_WARNING, "Unhandled signal %s", strsignal(sig));
			break;
	}
}
 
void daemonShutdown(){
	close(pidFilehandle);
	closelog();
}

//
// ler endereco ip e porta com suporte a pilha dupla
// 0.0.0.0:port para ipv4 ou [xxxx:hhhh::nnnn]:port
//
void read_addr_and_port(struct struct_cross* result, char *input, int totype){
	int len = 0;
	int idx = 0;
	int i;
	int cc = 0;
	int cd = 0;
	char addr[200];
	char port[6];
	int port_number = 0;
	int ai_family = 0;
	struct in_addr ipv4;

	memset(&addr, 0, 200);
	memset(&port, 0, 6);

	len = strlen(input);
	if(!len || len > 190) return;

	if(input[idx]=='['){
		// ipv6 com notacao
		ai_family = AF_INET6;

		// notacao ipv6
		idx++;
		for(i=idx;i<len;i++){
			char m;
			m=input[i];
			idx=i;
			if(!m) break;
			if(m==']'){
				// avancar para depois da notacao e parar
				idx++;
				break;
			}
			addr[i-1] = m;
		}
	
	}else{
		// ipv6 ou ipv4
		for(i=0;i<len;i++){
			char m;
			m=input[i];
			idx=i;
			if(!m) break;

			// contagem de pontos indica ipv4
			if(m=='.') cd++;

			// contagem de : indica ipv6 ou separacao ipv4:porta
			if(m==':'){
				cc++;
				if(!cd){
					// : sem pontos anteriores, indica familia ipv6
					ai_family = AF_INET6;
				}else{
					// pontos encontrados, seguidos de :, familia ipv4
					ai_family = AF_INET;
					
					// parar
					break;
				}
			}
			addr[i] = m;
		}
	}
	
	// familia padrao: ipv4
	if(!ai_family) ai_family = AF_INET;

	// ler porta
	if(idx<len){
		int j = 0;
		for(i=idx; i<len && j < 5;i++){
			char m;
			m=input[i];
			if(m==':') continue;
			if(m >= 48 && m <= 57) port[j++] = m;
		}	
	}

	// conversao string para binario
	
	// Porta e familia
	port_number = atoi(port);
	switch(totype){
		case 0: // local (server)
			result->local_portnumber = port_number;
			result->server_family = ai_family;
			break;
		case 1: // remote (destination)
			result->remote_portnumber = port_number;
			result->remote_family = ai_family;
			break;
	}

	// Endereco
	switch(ai_family){

	// IPv4
		case AF_INET:
			// converter string addr para ipv4 - 32 bits
			inet_pton(AF_INET, (const char *)addr, &(ipv4.s_addr) );
			
			// destinar a variavel adequada
			switch(totype){
				case 0: // local (server)
					result->server4_addr.sin_addr.s_addr = ipv4.s_addr;
					break;
				case 1: // remote (destination)
					result->remote4_addr.sin_addr.s_addr = ipv4.s_addr;
					break;
			}		
			break;

	// IPv6
		case AF_INET6:
			// converter string addr para ipv6 - 128 bits
			switch(totype){
				case 0: // local (server)
					inet_pton(AF_INET6, addr, &(result->server6_addr.sin6_addr));
					break;
				case 1: // remote (destination)
					inet_pton(AF_INET6, addr, &(result->remote6_addr.sin6_addr));
					break;
			}
	}
	// printf(" --> type[%d] FAMILY: %d INPUT: %s ADDR: %s PORT: %s PORT NUMBER: %d\n", totype, ai_family, input, addr, port, port_number);
}

void load_argv_config(int argc, char *argv[]){
	int argv_option;
	int tmp_idx;
	
	// tamanho padrao do buffer
	CrossOver.buffer_size = 4096;

	// processar parametros um a um
	do {
		argv_option = getopt_long(argc, argv, "", options_table, &tmp_idx);
		switch (argv_option){
			case LOCAL_OPTION: read_addr_and_port(&CrossOver, optarg, 0); break;
			case REMOTE_OPTION: read_addr_and_port(&CrossOver, optarg, 1); break;

			case BUFFER_SIZE_OPTION: CrossOver.buffer_size = atoi(optarg); break;		
			case DEBUG_OPTION: CrossOver.debug++; break;
			case PIDFILE_OPTION: CrossOver.pidfile = optarg; CrossOver.have_pidfile=1; break;
			case HELP_OPTION: print_help(); break;
			case VERSION_OPTION: print_version(); break;
			case '?': print_helpinfo(); break;
		}
	}
	while (argv_option != -1);

	// falta porta local
	if(!CrossOver.local_portnumber) abort_missing("missing local port on --local");

	// falta porta remota
	if(!CrossOver.remote_portnumber) abort_missing("missing remote port on --remote");

	// falta ip remoto
	switch(CrossOver.remote_family){
		case AF_INET:
			// Servidor em IPv4
			if(isempty_in_addr(&CrossOver.remote4_addr.sin_addr)) abort_missing("missing remote ipv4 address on --remote");
			break;

		case AF_INET6:
			// Servidor em IPv6
			if(isempty_in6_addr(&CrossOver.remote6_addr.sin6_addr)) abort_missing("missing remote ipv6 address on --remote");
			break;

		default:
			abort_missing("unknow protocol family, missing local address and port on --local");

	}


}

// Abrir porta TCP local em IPv4
int build_server_ipv4(void){
	CrossOver.server4_addr.sin_port = htons(CrossOver.local_portnumber);
	CrossOver.server4_addr.sin_family = AF_INET;

	CrossOver.server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (CrossOver.server_socket < 0){ perror("build_server: socket()"); return 1; }

	int optval = 1;
	if (setsockopt(CrossOver.server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0){
		perror("build_server: setsockopt(SO_REUSEADDR)");
		return 1;
	}

	if (bind(CrossOver.server_socket, (struct sockaddr *) &CrossOver.server4_addr, sizeof(CrossOver.server4_addr)) < 0){
		perror("build_server: bind()");
		return 1;
	}

	if (listen(CrossOver.server_socket, 1) < 0){
		perror("build_server: listen()");
		return 1;
	}

	return 0;
}

// Abrir porta TCP local em IPv6
int build_server_ipv6(void){
	CrossOver.server6_addr.sin6_flowinfo = 0;
	CrossOver.server6_addr.sin6_port = htons(CrossOver.local_portnumber);
	CrossOver.server6_addr.sin6_family = AF_INET6;

	CrossOver.server_socket = socket(AF_INET6, SOCK_STREAM, 0);
	if (CrossOver.server_socket < 0){ perror("build_server: socket()"); return 1; }
	
	int optval = 1;
	if (setsockopt(CrossOver.server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0){
		perror("build_server: setsockopt(SO_REUSEADDR)");
		return 1;
	}

	if (bind(CrossOver.server_socket, (struct sockaddr *) &CrossOver.server6_addr, sizeof(CrossOver.server6_addr)) < 0){
		perror("build_server: bind()");
		return 1;
	}

	if (listen(CrossOver.server_socket, 1) < 0){
		perror("build_server: listen()");
		return 1;
	}

	return 0;
}


// Construir servidor - abrir porta TCP local
int build_server(void){
	switch(CrossOver.server_family){
		case AF_INET: return build_server_ipv4(); break;
		case AF_INET6: return build_server_ipv6(); break;
	}
	return 2;
}

// Receber conexao de entrada (cliente pedindo conexao)
int wait_for_clients(void){
	int client_addr_size;

	// tamanho maximo da string
	char client_str[INET6_ADDRSTRLEN];
	bzero(client_str, INET6_ADDRSTRLEN);


	// Familia do cliente e' a mesma do servidor, obter tamanho do endereco IP (4 ou 32 bytes)
	client_addr_size = (CrossOver.server_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6) );

	// Coletar conexao na fila
	
	CrossOver.client_socket = (CrossOver.server_family == AF_INET ?
			accept((socklen_t)CrossOver.server_socket, (struct sockaddr *) &CrossOver.client4_addr, &client_addr_size)	
		:
			accept((socklen_t)CrossOver.server_socket, (struct sockaddr *) &CrossOver.client6_addr, &client_addr_size)
	);
	if (CrossOver.client_socket < 0){ if (errno != EINTR) perror("wait_for_clients: accept()"); return 1; }

	if (CrossOver.debug){	
		// obter ip do cliente
		if(CrossOver.server_family == AF_INET){
			// ipv4
			inet_ntop(AF_INET, &(CrossOver.client4_addr.sin_addr), client_str, INET_ADDRSTRLEN);
		}else{
			// ipv6
			inet_ntop(AF_INET6, &(CrossOver.client6_addr.sin6_addr), client_str, INET6_ADDRSTRLEN);
		}
		syslog(LOG_INFO, "Incomming request from %s\n", client_str);
	}
	return 0;
}

void handle_client(void){

	// Criar processo filho para atender o cliente
	if (fork() == 0){
		// fechar ponteiro parente
		close(CrossOver.server_socket);
		
		// criar tunnel tcp-tcp
		handle_tunnel();
		
		// acabou, apagar as luzes
		daemonShutdown();
		exit(0);
	}
	close(CrossOver.client_socket);

}

void handle_tunnel(void){
	if (make_remote_connection() == 0) use_tunnel();
}

// Criar conexao remota IPv4
int make_remote_connection_ipv4(void){
	CrossOver.remote4_addr.sin_family = AF_INET;
	CrossOver.remote4_addr.sin_port = htons(CrossOver.remote_portnumber);

	CrossOver.remote_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (CrossOver.remote_socket < 0){ perror("make_remote_connection: socket()"); return 1; }

	if (connect(CrossOver.remote_socket, (struct sockaddr *) &CrossOver.remote4_addr, sizeof(CrossOver.remote4_addr)) < 0){
		perror("make_remote_connection: connect()");
		return 1;
	}
	return 0;
}

// Criar conexao remota IPv6
int make_remote_connection_ipv6(void){
	CrossOver.remote6_addr.sin6_family = AF_INET6;
	CrossOver.remote6_addr.sin6_port = htons(CrossOver.remote_portnumber);

	CrossOver.remote_socket = socket(AF_INET6, SOCK_STREAM, 0);
	if (CrossOver.remote_socket < 0){ perror("make_remote_connection: socket()"); return 1; }

	if (connect(CrossOver.remote_socket, (struct sockaddr *) &CrossOver.remote6_addr, sizeof(CrossOver.remote6_addr)) < 0){
		perror("make_remote_connection: connect()");
		return 1;
	}
	return 0;
}

// Criar conexao remota
int make_remote_connection(void){
	switch(CrossOver.remote_family){
		case AF_INET: return make_remote_connection_ipv4(); break;
		case AF_INET6: return make_remote_connection_ipv6(); break;
	}
	return 0;
}

// Ambas as conexoes (cliente de entrada e conexao remota) estabelecidas, encaminhar trafego
int use_tunnel(void){
	fd_set io;
	char buffer[CrossOver.buffer_size];

	for (;;){

		FD_ZERO(&io);
		FD_SET(CrossOver.client_socket, &io);
		FD_SET(CrossOver.remote_socket, &io);

		memset(buffer, 0, sizeof(buffer));

		if (select(fix_filedescriptor(), &io, NULL, NULL, NULL) < 0){
			perror("use_tunnel: select()");
			break;
		}

		if (FD_ISSET(CrossOver.client_socket, &io)){
			int count = recv(CrossOver.client_socket, buffer, sizeof(buffer), 0);
			if (count < 0){
				perror("use_tunnel: recv(CrossOver.client_socket)");
				close(CrossOver.client_socket);
				close(CrossOver.remote_socket);
				return 1;
			}

			if (count == 0){
				close(CrossOver.client_socket);
				close(CrossOver.remote_socket);
				return 0;
			}

			send(CrossOver.remote_socket, buffer, count, 0);

			// Jogar conteudo do pacote na tela
			if (CrossOver.debug > 1 ){
				printf("> %s > ", make_date_str());
				fwrite(buffer, sizeof(char), count, stdout);
				fflush(stdout);
			}

		}

		if (FD_ISSET(CrossOver.remote_socket, &io)){
			int count = recv(CrossOver.remote_socket, buffer, sizeof(buffer), 0);
			if (count < 0){
				perror("use_tunnel: recv(CrossOver.remote_socket)");
				close(CrossOver.client_socket);
				close(CrossOver.remote_socket);
				return 1;
			}

			if (count == 0){
				close(CrossOver.client_socket);
				close(CrossOver.remote_socket);
				return 0;
			}

			send(CrossOver.client_socket, buffer, count, 0);

			if (CrossOver.debug > 1){
				fwrite(buffer, sizeof(char), count, stdout);
				fflush(stdout);
			}
		}
	}

	return 0;
}

int fix_filedescriptor(void){
	unsigned int fd = CrossOver.client_socket;
	if (fd < CrossOver.remote_socket) fd = CrossOver.remote_socket;
	return fd + 1;
}

int isempty_in6_addr(struct in6_addr *in6addr){
	int isum = 0;
	register int i;
	for(i=0;i<16;i++) isum+=in6addr->s6_addr[i];
	return isum ? 0 : 1;
}
int isempty_in_addr(struct in_addr *inaddr){
	return inaddr->s_addr ? 0 : 1;
}

/*
	Imprimir estrutura in_addr - representacao numerica/binaria do ipv4

	struct in_addr {
		unsigned long s_addr;  // load with inet_aton()
	};
*/
void print_in_addr(struct in_addr *inaddr){
    char str4[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(inaddr->s_addr), str4, INET_ADDRSTRLEN);
	printf("   struct in_addr: unsigned long s_addr: %s\n", str4);
}

/*
	Imprimir estrutura in_addr - representacao numerica/binaria do ipv6 em array de 16 posicoes
	struct in6_addr {
		unsigned char   s6_addr[16];   // IPv6 address
	};
*/
void print_in6_addr(struct in6_addr *in6addr){
    char str6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, in6addr, str6, INET6_ADDRSTRLEN);
	printf("   struct in6_addr:\n");
	printf("    unsigned char s6_addr[16]: ");
	printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x -> [%s]\n",
		in6addr->s6_addr[0], in6addr->s6_addr[1], in6addr->s6_addr[2], in6addr->s6_addr[3],
		in6addr->s6_addr[4], in6addr->s6_addr[5], in6addr->s6_addr[6], in6addr->s6_addr[7],
		in6addr->s6_addr[8], in6addr->s6_addr[9], in6addr->s6_addr[10], in6addr->s6_addr[11],
		in6addr->s6_addr[12], in6addr->s6_addr[13], in6addr->s6_addr[14], in6addr->s6_addr[15],
		str6
	);
}

/*
	Imprimir estrutura sockaddr_in6 - socket para envio e recebimento de ipv6

	struct sockaddr_in6 {
		sa_family_t     sin6_family;   // AF_INET6
		in_port_t       sin6_port;     // port number
		uint32_t        sin6_flowinfo; // IPv6 flow information
		struct in6_addr sin6_addr;     // IPv6 address
		uint32_t        sin6_scope_id; // Scope ID (new in 2.4)
	};
	struct in6_addr {
		unsigned char   s6_addr[16];   // IPv6 address
	};
*/
void print_sockaddr_in6(struct sockaddr_in6 *sin6){
	printf("  struct sockaddr_in6:\n");
	printf("  .u_char sin6_len...........: %d ", sin6->sin6_family);
	printf("  .in_port_t sin6_port.......: %d\n", sin6->sin6_port);
	printf("  .u_char sin6_flowinfo......: %d ", sin6->sin6_flowinfo);
	print_in6_addr(&sin6->sin6_addr);
	printf("  .u_char sin6_len...........: %d\n", sin6->sin6_scope_id);
}

/*
	Imprimir estrutura sockaddr_in - socket para envio e recebimento de ipv4

	struct sockaddr_in {
		short            sin_family;   // e.g. AF_INET
		unsigned short   sin_port;     // e.g. htons(3490)
		struct in_addr   sin_addr;     // see struct in_addr, below
		char             sin_zero[8];  // zero this if you want to
	};
	
	struct in_addr {
		unsigned long s_addr;  // load with inet_aton()
	};

*/
void print_sockaddr_in(struct sockaddr_in *sin){
	printf("  struct sockaddr_in:\n");
	printf("  .short sin_family...........: %d ", sin->sin_family);
	printf("  .unsigned short.............: %d\n", sin->sin_port);
	printf("  .struct in_addr.............:\n");
	print_in_addr(&sin->sin_addr);
	printf("  .char sin_zero..............: %d %d %d %d %d %d %d %d\n", sin->sin_zero[0], sin->sin_zero[1], sin->sin_zero[2], sin->sin_zero[3], sin->sin_zero[4], sin->sin_zero[5], sin->sin_zero[6], sin->sin_zero[7]);
}

void print_crossover(struct struct_cross *cross){
	printf("Have buffer size.........: %d\n", cross->have_buffer_size);
	printf("Have have pid file.......: %d\n", cross->have_pidfile);

	printf("Server socket............: %d\n", cross->server_socket);
	printf("Client socket............: %d ", cross->client_socket);
	printf("Remote socket............: %d\n", cross->remote_socket);

	printf("SERVER FAMILY............: %d %s\n", cross->server_family, (cross->server_family == AF_INET ? "IPv4" : "IPv6"));
	printf("REMOTE FAMILY............: %d %s\n", cross->remote_family, (cross->remote_family == AF_INET ? "IPv4" : "IPv6"));

	printf("Sockaddr IN6 server6_addr:\n");
	print_sockaddr_in6(&cross->server6_addr);

	printf("Sockaddr IN6 client6_addr:\n");
	print_sockaddr_in6(&cross->client6_addr);
	
	printf("Sockaddr IN6 remote6_addr:\n");
	print_sockaddr_in6(&cross->remote6_addr);

	printf("Sockaddr IN server4_addr:\n");
	print_sockaddr_in(&cross->server4_addr);

	printf("Sockaddr IN client4_addr:\n");
	print_sockaddr_in(&cross->client4_addr);
	
	printf("Sockaddr IN remote4_addr:\n");
	print_sockaddr_in(&cross->remote4_addr);

	printf("PidFile..................: %s\n", cross->pidfile);

	printf("Local port number........: %d\n", cross->local_portnumber);
	printf("Remote port number.......: %d\n", cross->remote_portnumber);
	printf("Buffer size..............: %d\n", cross->buffer_size);

}

char *make_date_str(void){
	static char date_str[20];
	time_t date;

	time(&date);
	strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S", localtime(&date));
	return date_str;
}

void print_helpinfo(void){ fprintf(stderr, "Usage: %s [options]\n\n", DAEMON_NAME); fprintf(stderr, "Try `%s --help' for more options\n", DAEMON_NAME); exit(1); }
void print_help(void){
	fprintf(stderr, "Usage: %s [options]\n\n", DAEMON_NAME);

	fprintf(stderr, "Options:\n\
  --version\n\
  --help\n\n\
  --local         local addrress and port to bind, sample: [::]:80, [2001:cafe::1234]:80\n\
  --remote        remote address and port to connect, sample: 192.168.0.2:80, [2804:bebe:cafe::1]:80\n\
  --bs=BYTES      buffer size\n\
  --pidfile=FILE  set pidfile\n\
  --debug         enable debug\n\
  --log           enable log\n\n");
  	exit(1);
}
void print_version(void){
	fprintf(stderr, "\n\ntcp-cross64 " VERSION " written by Patrick Brandao <patrickbrandao@gmail.com>\n");
 	fprintf(stderr, "\n");
	fprintf(stderr, "   Copyright (C) 2015 Patrick Brandao <patrickbrandao@gmail.com>\n");
 	fprintf(stderr, "\n");
	fprintf(stderr, "   This program is free software; you can redistribute it and/or modify\n");
	fprintf(stderr, "   it under the terms of the GNU General Public License as published by\n");
	fprintf(stderr, "   the Free Software Foundation; either version 2 of the License, or\n");
	fprintf(stderr, "   (at your option) any later version.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   This program is distributed in the hope that it will be useful,\n");
	fprintf(stderr, "   but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
	fprintf(stderr, "   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
	fprintf(stderr, "   GNU General Public License for more details.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   You should have received a copy of the GNU General Public License\n");
	fprintf(stderr, "   along with this program; if not, write to the Free Software\n");
	fprintf(stderr, "   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307\n");
	fprintf(stderr, "   USA\n\n");
	exit(1);
}
void abort_missing(const char *message){ fprintf(stderr, "%s: %s\n", DAEMON_NAME, message); print_helpinfo(); }
void abort_failure(const char *message){ fprintf(stderr, "%s: %s\n", DAEMON_NAME, message); exit(1); }

