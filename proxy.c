#include<errno.h>
#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdio.h>
#include<sys/epoll.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netdb.h>

/* Recommended max cache and object sizes */
#define MAX_CACHE_SIZE 1049000
#define MAX_OBJECT_SIZE 102400
#define MAXEVENTS 64
#define MAXLINE 2048
#define RD_REQUEST 1
#define SEND_REQUEST 2
#define RD_RESPONSE 3
#define SEND_RESPONSE 4

struct client_info {
	int client_fd;
	int server_fd;
	int state;
	char c_reqs_buff[MAX_OBJECT_SIZE];
	char s_reqs_buff[MAX_OBJECT_SIZE];
	char s_resp_buff[MAX_OBJECT_SIZE];
	int nbytes_read_from_client;
	int nbytes_to_write_server;
	int nbytes_written_server;
	int nbytes_read_from_server;
	int nbytes_written_client;
};

static const char *user_agent_hdr = "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:97.0) Gecko/20100101 Firefox/97.0";

int all_headers_received(char *);
int parse_request(char *, char *, char *, char *, char *, char *);
void test_parser();
void print_bytes(unsigned char *, int);
int open_sfd(int port);
void handle_new_clients(int fd, int efd);
void handle_client(struct client_info* client, int epoll_fd);


int main(int argc, char *argv[])
{
	int port;
	int efd;
	struct client_info *listener;
	struct epoll_event event;
	struct epoll_event events[MAXEVENTS];
	int i;
	struct client_info *active_client;
	size_t n; 


	//test_parser();
	if(argc == 2){
		port = atoi(argv[1]);
	} else{
		printf("need port number");
		return 0;
	}

	int sfd = open_sfd(port);

	if ((efd = epoll_create1(0)) < 0) {
		perror("Error with epoll_create1");
		exit(EXIT_FAILURE);
	}

	listener = malloc(sizeof(struct client_info));
	listener->client_fd = sfd;


	event.data.ptr = listener;
	event.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event) < 0) {
		fprintf(stderr, "error adding event\n");
		exit(EXIT_FAILURE);
	}

	while (1) {
		n = epoll_wait(efd, events, MAXEVENTS, 1000);

		for (i = 0; i < n; i++) {
			active_client = (struct client_info *)(events[i].data.ptr);

			printf("New event for fd %d\n", active_client->client_fd);

			if (sfd == active_client->client_fd) {
				handle_new_clients(sfd, efd);
			} else {
				handle_client(active_client, efd);
			}
		}
	}
	free(listener);
}

void handle_client(struct client_info* client, int epoll_fd){
	printf("DEBUG: Client Entered Handle Client FD: %d, State: %d", client->client_fd, client->state);
	fflush(stdout);
	if(client->state == RD_REQUEST){
		char method[16], hostname[64], port[8], path[64], headers[1024];
		bzero(method, 16);
		bzero(hostname, 64);
		bzero(port, 8);
		bzero(path, 64);
		bzero(headers, 1024);
		int bytes_received = 0;

		//if we don't have the whole request
		while(!parse_request(client->c_reqs_buff, method, hostname, port, path, headers)){
			bytes_received = recv(client->client_fd, client->c_reqs_buff + client->nbytes_read_from_client, MAX_OBJECT_SIZE, 0);
			if(bytes_received < 0) {
				if (errno == EWOULDBLOCK || errno == EAGAIN) return;
				else {
					perror("recv()");
					close(client->client_fd);
					free(client);
					return;
				}
   			}
			client->nbytes_read_from_client += bytes_received;
		}
		//we now have the whole client request 

		//make http request
				char host[73];
		//printf("%s\n", port);
		if(strcmp(port, "80") == 0){
			snprintf(host, 73, "%s", hostname);
		} else {
			snprintf(host, 73, "%s:%s", hostname, port);
		}

		bzero(client->s_reqs_buff, MAX_OBJECT_SIZE);
		snprintf(client->s_reqs_buff, MAX_OBJECT_SIZE, "%s %s HTTP/1.0\r\n"
											"Host: %s\r\n"
											"User-Agent: %s\r\n"
											"Connection: close\r\n"
											"Proxy-Connection: close\r\n\r\n",
											method, path, host, user_agent_hdr);
		client->nbytes_to_write_server = strlen(client->s_reqs_buff);

		//printf("%s", client->s_reqs_buff);
		//fflush(stdout);

		//create new server socket
		struct addrinfo hints;
		struct addrinfo *result, *rp;
		int s_sock;

		
		int addr_fam;
		socklen_t addr_len;

		struct sockaddr_in remote_addr_in;
		char remote_addr_str[INET6_ADDRSTRLEN];
		struct sockaddr *remote_addr;



		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = 0;
		hints.ai_protocol = 0;


		s_sock = getaddrinfo(hostname, port, &hints, &result);
		if (s_sock != 0) {
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s_sock));
			exit(EXIT_FAILURE);
		}

		for (rp = result; rp != NULL; rp = rp->ai_next) {
			client->server_fd = socket(rp->ai_family, rp->ai_socktype,
					rp->ai_protocol);
			if (client->server_fd == -1)
				continue;

			addr_fam = rp->ai_family;
			addr_len = rp->ai_addrlen;

			remote_addr_in = *(struct sockaddr_in *)rp->ai_addr;
			inet_ntop(addr_fam, &remote_addr_in.sin_addr,
					remote_addr_str, addr_len);
			remote_addr = (struct sockaddr *)&remote_addr_in;

			if (connect(client->server_fd, remote_addr, addr_len) != -1){
				//set to non blocking
				if (fcntl(client->server_fd, F_SETFL, fcntl(client->server_fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
					fprintf(stderr, "error setting socket option\n");
					exit(1);
				}


				//register socket with epoll
				struct epoll_event event;
				event.data.ptr = client;
				event.events = EPOLLOUT | EPOLLET;
				if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client->server_fd, &event) < 0) {
					perror("Error registering socket with epoll");
					close(epoll_fd);
					close(client->server_fd);
					return;
				}

				//printf("connected");
				break;  
			} else{
				printf("not connected");
			}

			close(client->server_fd);
		}
		client->state = 2;
		printf("end of read request"); fflush(stdout);
	} 

	//if client is in state 2
	if(client->state == SEND_REQUEST){
		while(client->nbytes_written_server != client->nbytes_to_write_server){
			int bytes_sent = send(client->server_fd, client->s_reqs_buff, strlen(client->s_reqs_buff), 0);
			if(bytes_sent < 0) {
				if (errno == EWOULDBLOCK || errno == EAGAIN) return;
				else {
					perror("recv()");
					close(client->client_fd);
					free(client);
					return;
				}
			}
   		
			client->nbytes_written_server += bytes_sent;
		}

		struct epoll_event event;
		event.data.ptr = client;
		event.events = EPOLLIN | EPOLLET;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->server_fd, &event) < 0) {
			perror("Error registering socket with epoll");
			close(epoll_fd);
			close(client->server_fd);
			return;
		}

		client->state = RD_RESPONSE;
		printf("End of Send_request");
		fflush(stdout);
	}

	//if client is in read response 3
	if(client->state == RD_RESPONSE){
		int bytes_received = -1;
		while(bytes_received != 0){
			//printf("BYTESRECEIVED %d", bytes_received); fflush(stdout);
		    bytes_received = read(client->server_fd, client->s_resp_buff + client->nbytes_read_from_server, MAX_OBJECT_SIZE);
			//printf("\nBYTESRECEIVED 2 %d", bytes_received); fflush(stdout);
			//printf(" ERROR: %d", errno); fflush(stdout);
			if(bytes_received < 0) {
				if (errno == EWOULDBLOCK || errno == EAGAIN) return;
				else {
					perror("recv()");
					close(client->client_fd);
					free(client);
					return;
				}
			}
   		
			client->nbytes_read_from_server += bytes_received;
		}
		close(client->server_fd);

		//register the client-to-proxy socket with the epoll instance for writing.
		struct epoll_event event;
		event.data.ptr = client;
		event.events = EPOLLOUT | EPOLLET;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->client_fd, &event) == -1) {
			perror("epoll_ctl error");
			exit(EXIT_FAILURE);
		}
		printf("Server Response: %s", client->s_resp_buff);
		fflush(stdout);
		client->state = SEND_RESPONSE;
	}

	if(client->state == SEND_RESPONSE){
		while(client->nbytes_written_client != client->nbytes_read_from_server){
			int bytes_sent = send(client->client_fd, client->s_resp_buff, client->nbytes_read_from_server, 0);
			if(bytes_sent < 0) {
				if (errno == EWOULDBLOCK || errno == EAGAIN) return;
				else {
					perror("recv()");
					close(client->client_fd);
					free(client);
					return;
				}
			}
   		
			client->nbytes_written_client += bytes_sent;
		}
		close(client->client_fd);
	}
}

int open_sfd(int port){
	int domain = AF_INET;
	int type = SOCK_STREAM;
	int sfd = socket(domain, type, 0);

	int optval = 1;
	setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

	//bind
	struct sockaddr *local_addr;
	socklen_t local_addr_len;
	struct sockaddr_in ipv4addr;

	ipv4addr.sin_family = domain;
	ipv4addr.sin_addr.s_addr = INADDR_ANY;
	ipv4addr.sin_port = htons(port);

	local_addr = (struct sockaddr *)&ipv4addr;
	local_addr_len = sizeof(ipv4addr);

	if(bind(sfd, local_addr, local_addr_len) < 0){
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(sfd, SOMAXCONN) < 0) { 
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

	if (fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL, 0) | O_NONBLOCK) < 0) {
		fprintf(stderr, "error setting socket option\n");
		exit(1);
	}

	return sfd;
}

void handle_new_clients(int sfd, int efd){
	socklen_t remote_addr_len;
	struct sockaddr_storage *remote_addr;
	int connfd;
	struct client_info *new_client;
	struct epoll_event event;

	while (1) {
		remote_addr_len = sizeof(struct sockaddr_storage);
		connfd = accept(sfd, (struct sockaddr *)&remote_addr, &remote_addr_len);

		if (connfd < 0) {
			if (errno == EWOULDBLOCK ||
					errno == EAGAIN) {
				// no more clients ready to accept
				break;
			} else {
				perror("accept");
				exit(EXIT_FAILURE);
			}
		}

		// set client file descriptor non-blocking
		if (fcntl(connfd, F_SETFL, fcntl(connfd, F_GETFL, 0) | O_NONBLOCK) < 0) {
			fprintf(stderr, "error setting socket option\n");
			exit(1);
		}

		// allocate memory for a new struct
		// client_info, and populate it with
		// info for the new client
		new_client = (struct client_info *)malloc(sizeof(struct client_info));
		new_client->client_fd = connfd;
		new_client->server_fd = -1;
		new_client->state = RD_REQUEST;
		//want 2 fd for each client need a client fd and server fd

		// register the client file descriptor
		// for incoming events using
		// edge-triggered monitoring
		event.data.ptr = new_client;
		event.events = EPOLLIN | EPOLLET;
		if (epoll_ctl(efd, EPOLL_CTL_ADD, connfd, &event) < 0) {
			fprintf(stderr, "error adding event\n");
			exit(1);
		}
	}
}

int all_headers_received(char *request) {
	return 0;
}

int parse_request(char *request, char *method, char *hostname, char *port, char *path, char *headers) {
    //make request copy so we can use strtok which will change the request copy by adding in null characters
    char request_copy[strlen(request) + 1];
    strcpy(request_copy, request);

    //pointer to where in request the end is found
    char* end = strstr(request_copy, "\r\n\r\n");
	if (end == NULL){
		return 0;
	}

    //get the method
    char* first_space = strchr(request_copy, ' ');
    int length = first_space - request_copy;
    memcpy(method, request_copy, length);
	method[length] = '\0';

    //get the URL
    char* second_space = strchr(first_space + 1, ' ');
    int url_length = second_space - first_space - 1;
    char url[url_length + 1];
    memcpy(url, first_space + 1, url_length);
    url[url_length] = '\0';
    //printf("URL: %s \n", url);

	//parse URL
	char* first_colon = strstr(url, "://");
	char* second_colon = strchr(first_colon + 1, ':');
	//No second Colon
	if(second_colon == NULL){
		strcpy(port, "80");
		char* next_slash = strchr(first_colon + 3, '/');
		length = next_slash - first_colon - 3;
		memcpy(hostname, first_colon + 3, length);
		hostname[length] = '\0';
		memcpy(path, next_slash, url_length);
		path[url_length] = '\0';
	}
	//second colon 
	else{
		char* next_slash = strchr(first_colon + 3, '/');
		length = next_slash - second_colon - 1;
		memcpy(port, second_colon + 1, length);
		port[length] = '\0';
		length = second_colon - first_colon - 3;
		memcpy(hostname, first_colon + 3, length);
		hostname[length] = '\0';
		memcpy(path, next_slash, url_length);
		path[url_length] = '\0';
	}

    //get the headers
    char* endOfFirstLine = strstr(request_copy, "\r\n");
    length = end - endOfFirstLine - 2;
    memcpy(headers, endOfFirstLine + 2, length);
    headers[length] = '\0';

    //printf("Request: %s, Method: %s, Hostname: %s, port: %s, Path: %s, headers: %s \n", request, method, hostname, port, path, headers);
    return 1;
}

void test_parser() {
	int i;
	char method[16], hostname[64], port[8], path[64], headers[1024];

       	char *reqs[] = {
		"GET http://www.example.com/index.html HTTP/1.0\r\n"
		"Host: www.example.com\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n\r\n",

		"GET http://www.example.com:8080/index.html?foo=1&bar=2 HTTP/1.0\r\n"
		"Host: www.example.com:8080\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n\r\n",

		"GET http://localhost:1234/home.html HTTP/1.0\r\n"
		"Host: localhost:1234\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n\r\n",

		"GET http://www.example.com:8080/index.html HTTP/1.0\r\n",

		NULL
	};
	
	for (i = 0; reqs[i] != NULL; i++) {
		printf("Testing %s\n", reqs[i]);
		if (parse_request(reqs[i], method, hostname, port, path, headers)) {
			printf("METHOD: %s\n", method);
			printf("HOSTNAME: %s\n", hostname);
			printf("PORT: %s\n", port);
			printf("HEADERS: %s\n", headers);
		} else {
			printf("REQUEST INCOMPLETE\n");
		}
	}
}

void print_bytes(unsigned char *bytes, int byteslen) {
	int i, j, byteslen_adjusted;

	if (byteslen % 8) {
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	} else {
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++) {
		if (!(i % 8)) {
			if (i > 0) {
				for (j = i - 8; j < i; j++) {
					if (j >= byteslen_adjusted) {
						printf("  ");
					} else if (j >= byteslen) {
						printf("  ");
					} else if (bytes[j] >= '!' && bytes[j] <= '~') {
						printf(" %c", bytes[j]);
					} else {
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted) {
				printf("\n%02X: ", i);
			}
		} else if (!(i % 4)) {
			printf(" ");
		}
		if (i >= byteslen_adjusted) {
			continue;
		} else if (i >= byteslen) {
			printf("   ");
		} else {
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}
