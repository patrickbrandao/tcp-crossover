#ifndef TCPCROSSOVER_H
#define TCPCROSSOVER_H

#define VERSION "0.2"

#define LOCAL_OPTION		'a'
#define REMOTE_OPTION		'b'
#define PIDFILE_OPTION      'c'
#define BUFFER_SIZE_OPTION  'd'
#define DEBUG_OPTION        'e'
#define HELP_OPTION         'f'
#define VERSION_OPTION      'g'

#define DAEMON_NAME "tcp-crossover"

// Controle de processo 
void daemonShutdown();
void signal_handler(int sig);

// Funcoes de conexao
void server_start();
int build_server(void);
int wait_for_clients(void);
void handle_client(void);
void handle_tunnel(void);

int make_remote_connection(void);
int make_remote_connection_ipv4(void);
int make_remote_connection_ipv6(void);

int use_tunnel(void);
int fix_filedescriptor(void);

void load_argv_config(int argc, char *argv[]);
void set_option(char **option, char *value);

char *make_date_str(void);

// Funcoes de suporte e depuracao
int isempty_in6_addr(struct in6_addr *in6addr);
int isempty_in_addr(struct in_addr *inaddr);
void print_in_addr(struct in_addr *inaddr);
void print_in6_addr(struct in6_addr *in6addr);
void print_sockaddr_in6(struct sockaddr_in6 *sin6);
void print_sin6_addr(struct in6_addr x6_addr);

// Funcoes de ajuda ao usuario
void print_help(void);
void print_helpinfo(void);
void print_version(void);
void abort_missing(const char *message);
void abort_failure(const char *message);

// Armazenamento de valores
struct struct_cross {
	unsigned int have_buffer_size  : 1;
	unsigned int have_pidfile      : 1;

	unsigned int server_socket;
	unsigned int client_socket;
	unsigned int remote_socket;

	// conexao de entrada
	int server_family;
	struct sockaddr_in6 server6_addr;
	struct sockaddr_in server4_addr;

	// cliente da conexao de entrada
	struct sockaddr_in6 client6_addr;
	struct sockaddr_in client4_addr;

	// Conexao com servidor remoto
	int remote_family;
	struct sockaddr_in6 remote6_addr;
	struct sockaddr_in remote4_addr;

	int local_portnumber;
	int remote_portnumber;

	unsigned int buffer_size;

	int debug;
	char *pidfile;
};

// debug de valores
void print_crossover(struct struct_cross *CrossOver);

#define SAPP struct struct_cross*
#define SAP struct struct_cross

void read_addr_and_port(struct struct_cross* result, char *input, int totype);


#endif

