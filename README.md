# tcp-crossover

Uma forma simples e rápida de fazer tuneis TCP com suporte a pilha dupla: IPv4 e IPv6

Alguns programas não possuem suporte a IPv6, especificamente, a capacidade de abrir a porta TCP em endereços IPv6.

Alguns exemplos disso são:
- Versões antigas de servidores HTTP
- Versões antigas de servidores SMTP, POP, IMAP
- Aplicações construidas por encomenda que não contam mais com capacidade de melhorias ou modificações.
- Aplicações com restrições de recursos para implementar pilha dupla

Esses problemas tornam a migração para o IPv6 economicamente inviavel. Para muitos, não adianta ter IPv6 distribuido e disponivel se os aplicativos continuam explorando apenas a pilha IPv4.

O TCP-CROSSOVER resolve esses problemas intermediando de maneira transparente o fluxo de dados entre a pilha IPv4 e IPv6.

Seu funcionamento é simples:
Ao abrir uma porta TCP na pilha IPv6, a conexão de entrada em IPv6 é atendida, enquanto isso o tcp-crossover estabelece uma conexão TCP com o destino IPv4 (no mesmo computador ou em outro) e repassa de forma transparente os dados entre elas.

Ele é capaz de:
- Dar suporte IPv6 a aplicativos puramente IPv4
- Fazer tunel TCP, com as possibilidades:
	1 - ipv4 para ipv4
	2 - ipv4 para ipv6
	3 - ipv6 para ipv4
	4 - ipv6 para ipv6

Para compilar:
	1 - baixe e descompecte o arquivo do projeto
	2 - execute:

		 make
		 make install

O binario será instalado em /usr/bin/tcp-crossover

Exemplos de como usar:

HTTP - ipv6 para ipv4:

    tcp-crossover --local [::]:80 --remote 127.0.0.1:80 --pidfile=/var/run/tcp-cross-http.pid

Abre a porta TCP/80 em IPv6 e encaminha para o ip de loopback na porta 80. Esse exemplo permite disponibilizar sites em IPv6 nos casos em que o software servidor HTTP não tem suporte IPv6.

SMTP - ipv6 para ipv6
    tcp-crossover --local [::]:25 --remote [2804:aabb:beba:cafe::ccdd]:25 --pidfile=/var/run/tcp-cross-smtp.pid

As conexoes destinadas a porta 25 em todos os enderecos IPv6 serao encaminhadas para outro endereco IPv6

Ajuda:

    tcp-crossover --help



