#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>

#include "dns.h"

#define RESPONSE_LEN 3
#define BUFFER_LEN 256

static int getsocket(const char ip[], const char port[]) {
    struct addrinfo hints,
                    *server_ai,
                    *p;
    int sockfd, ecode;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    ecode = getaddrinfo(ip, port, &hints, &server_ai);
    if (ecode != 0) {
        fprintf(stderr, "error: getaddrinfo: %s\n", gai_strerror(ecode));
        return -1;
    }

    p = &server_ai[0];

    for (p = &server_ai[0]; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("error: socket");
        } else {
            break;
        }
    }
    if (p == NULL) {
        return -1;
    }

    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
        perror("error: connect");
        return -1;
    }

    freeaddrinfo(server_ai);
    return sockfd;
}

void udp_send(uint8_t *buffer, int bsize, const char *ip, const char *port) {

    int len,sockfd;

    sockfd = getsocket(ip, port);

    if (sockfd == -1) {
        fprintf(stderr, "error: could not connect to %s port %s\n", ip, port);
        exit(1);
    }
    len = send(sockfd, buffer, bsize, 0);
    if (len == -1) {
        perror("error: send");
        close(sockfd);
        exit(1);
    }
    len = recv(sockfd, buffer, MESSAGE_MAXLEN, 0);
    if (len == -1) {
        perror("error: recv");
        close(sockfd);
        exit(1);
    }
    buffer[len] = '\0';
}
