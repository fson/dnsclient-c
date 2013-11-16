#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include "dns.h"
#include "udp.h"
#include <stdio.h>

#define LINE_MAX 80


/* Reads DNS server IP from /etc/resolv.conf */
char *getnameserver() {
    char *ns = NULL;
    char buffer[LINE_MAX];
    FILE *file = fopen("/etc/resolv.conf", "r");
    if (file == NULL) {
        fprintf(stderr, "Cannot read /etc/resolv.conf\n");
        return NULL;
    }
    while (fgets(buffer, LINE_MAX, file)) {
        if (strncmp(buffer, "nameserver ", 11) == 0) {
            ns = malloc(strlen(&buffer[11]) + 1);
            strcpy(ns, &buffer[11]);
            break;
        }
    }
    return ns;
}

int main(int argc, char *argv[]) {

    if (argc != 2) {
        fprintf(stderr, "Usage: ./dnsclient hostname\n");
        exit(-1);
    }

    uint8_t message_buffer[MESSAGE_MAXLEN];
    memset(message_buffer, 0, MESSAGE_MAXLEN);

    Message *query = dns_createmessage();

    // Set query header section
    query->header = dns_createheader();
    query->header->id = rand();
    query->header->flags = HEADER_RD;
    query->header->qdcount = 1;
    query->header->ancount = 0;
    query->header->nscount = 0;
    query->header->arcount = 0;

    // Set query question section
    query->question = dns_createquestion();
    dns_setqname(query->question->qname, argv[1]);
    query->question->qtype = QTYPE_A;
    query->question->qclass = QCLASS_IN;

    memset(message_buffer, 0, MESSAGE_MAXLEN);
    int bsize = dns_dumpmessage(query, message_buffer);

    char *nameserver = getnameserver();
    udp_send(message_buffer, bsize, nameserver, DNS_PORT_NUMBER_STR);

    Message *response = dns_parsemessage(message_buffer);

    if (response->header->ancount == 0) {
        printf("Not found\n");
        return -1;
    }

    Resource *ans;
    uint8_t *d;

    for (int i = 0; i < response->header->ancount; i++) {
        ans = response->answer[i];
        d = (uint8_t*)ans->rdata;
        if (ans->type == QTYPE_A && ans->rdlength == 4) {
            // print IPv4 address
            printf("%d.%d.%d.%d\n", d[0], d[1], d[2], d[3]);
        } else if (ans->type == QTYPE_AAAA) {
            // print IPv6 address
            for (int j = 0; j < 8; j++) {
                printf("%02x%02x", d[j], d[j + 1]);
                if (j < 7) printf(":");
            }
            printf("\n");
        }
    }

    return 0;
}
