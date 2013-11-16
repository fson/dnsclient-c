#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdio.h>

#include "dns.h"

#define DUMP_SHORT(FIELD, BUFFER, OFFSET, TEMP) \
    do { \
        (TEMP) = htons(FIELD); \
        memcpy(&(BUFFER)[(OFFSET)], &(TEMP), 2); \
        (OFFSET) += 2; \
    } while (0)

#define PARSE_RESOURCES(COUNT, FIELD, BUFFER, OFFSET) \
    do { \
        (FIELD) = calloc(sizeof(Resource), (COUNT)); \
        for (size_t parse_resources_i = 0; parse_resources_i < (COUNT); parse_resources_i++) { \
            (FIELD)[parse_resources_i] = dns_parseresource((BUFFER), &(OFFSET)); \
        } \
    } while (0)

#define PARSE_SHORT(FIELD, BUFFER, OFFSET, TEMP) \
    do { \
            memcpy(&(TEMP), &(BUFFER)[(OFFSET)], 2); \
            (OFFSET) += 2; \
            (FIELD) = ntohs(TEMP); \
    } while (0)

#define PARSE_LONG(FIELD, BUFFER, OFFSET, TEMP) \
    do { \
            memcpy(&(TEMP), &(BUFFER)[(OFFSET)], 4); \
            (OFFSET) += 4; \
            (FIELD) = ntohl(TEMP); \
    } while (0)

/*
 * Copies the contents of the Message to given buffer in DNS message format.
 *
 * Returns: number of resulting bytes
 *
 *  +---------------------+
 *  |        Header       |
 *  +---------------------+
 *  |       Question      | the question for the name server
 *  +---------------------+
 *  |        Answer       | RRs answering the question
 *  +---------------------+
 *  |      Authority      | RRs pointing toward an authority
 *  +---------------------+
 *  |      Additional     | RRs holding additional information
 *  +---------------------+
 */
int dns_dumpmessage(Message *message, uint8_t *buffer) {
    int offset = 0;

    offset += dns_dumpheader(message->header, buffer);
    offset += dns_dumpquestion(message->question, buffer + offset);

    // ignoring resource record sections

    return offset;
}

/*
 * Copies the contents of the Header to given buffer in DNS message format.
 *
 * Returns: number of resulting bytes
 *
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                      ID                       |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    QDCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ANCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    NSCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ARCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
int dns_dumpheader(Header *h, uint8_t *buffer) {
    uint16_t temp;
    int offset = 0;

    DUMP_SHORT(h->id, buffer, offset, temp);
    DUMP_SHORT(h->flags, buffer, offset, temp);
    DUMP_SHORT(h->qdcount, buffer, offset, temp);
    DUMP_SHORT(h->ancount, buffer, offset, temp);
    DUMP_SHORT(h->nscount, buffer, offset, temp);
    DUMP_SHORT(h->arcount, buffer, offset, temp);

    return offset;
}
/*
 * Copies the contents of the Header to given buffer in DNS message format.
 *
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                                               |
 *  /                     QNAME                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QTYPE                     |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QCLASS                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
int dns_dumpquestion(Question *q, uint8_t *buffer) {
    uint16_t temp = 0;
    int len = 0;
    int offset = 0;

    len = strlen(q->qname) + 1;
    memcpy(&buffer[offset], q->qname, len);
    offset += len;

    DUMP_SHORT(q->qtype, buffer, offset, temp);
    DUMP_SHORT(q->qclass, buffer, offset, temp);

    return offset;
}

/* Parses a message in DNS formatted message to a Message struct */
Message *dns_parsemessage(uint8_t *buffer) {
    int offset = 0;
    Message *m = dns_createmessage();
    m->header = dns_parseheader(buffer, &offset);
    m->question = dns_parsequestion(buffer, &offset);

    // answer section
    PARSE_RESOURCES(m->header->ancount, m->answer, buffer, offset);

    // authority and additional sections not implemented

    return m;
}

/* Parses a header section in DNS formatted message to a Header struct */
Header *dns_parseheader(uint8_t *buffer, int *offset) {
    uint16_t temp;
    Header *h = dns_createheader();

    PARSE_SHORT(h->id, buffer, *offset, temp);
    PARSE_SHORT(h->flags, buffer, *offset, temp);
    PARSE_SHORT(h->qdcount, buffer, *offset, temp);
    PARSE_SHORT(h->ancount, buffer, *offset, temp);
    PARSE_SHORT(h->nscount, buffer, *offset, temp);
    PARSE_SHORT(h->arcount, buffer, *offset, temp);
    return h;
}

/* Parses a question section in DNS formatted message to Question struct. */
Question *dns_parsequestion(uint8_t *buffer, int *offset) {
    int len;
    Question *q = dns_createquestion();
    len = strlen((char*)&buffer[*offset]) + 1;
    memcpy(q->qname, &buffer[*offset], len);
    *offset += len;

    uint16_t temp;
    PARSE_SHORT(q->qtype, buffer, *offset, temp);
    PARSE_SHORT(q->qclass, buffer, *offset, temp);

    return q;
}

/* Parses a resource record section in DNS formatted message to Resource struct. */
Resource *dns_parseresource(uint8_t *buffer, int *offset) {
    int p, len;
    uint16_t temp;
    uint32_t templ;
    Resource *r = dns_createresource();

    if (buffer[*offset] & 0xC0) { // compressed name
        PARSE_SHORT(p, buffer, *offset, temp);
        p &= 0x3F; // trim 2 first bits
        len = strlen((char*)&buffer[p]) + 1;
        r->name = calloc(sizeof(char), len);
        memcpy(r->name, &buffer[p], len);
    } else {
        len = strlen((char*)&buffer[*offset]) + 1;
        r->name = calloc(sizeof(char), len);
        memcpy(r->name, &buffer[*offset], len);
        *offset += len;
    }

    PARSE_SHORT(r->type, buffer, *offset, temp);
    PARSE_SHORT(r->class, buffer, *offset, temp);
    PARSE_LONG(r->ttl, buffer, *offset, templ);
    PARSE_SHORT(r->rdlength, buffer, *offset, temp);

    r->rdata = &buffer[*offset];

    return r;
}

Message *dns_createmessage() {
    return calloc(sizeof(Message), 1);
}

void dns_destroymessage(Message *m) {
    if (m->header) {
        dns_destroyheader(m->header);
    }
    if (m->question) {
        dns_destroyquestion(m->question);
    }
    free(m);
}

Header *dns_createheader() {
    Header *header = calloc(sizeof(Header), 1);
    return header;
}

void dns_destroyheader(Header *h) {
    free(h);
}

Question *dns_createquestion() {
    Question *q = calloc(sizeof(Question), 1);
    q->qname = calloc(QNAME_MAXLEN + 1, 1);
    return q;
}

void dns_destroyquestion(Question *q) {
    free(q->qname);
    free(q);
}

int dns_setqname(char *qname, const char *name) {
    if (strlen(name) > QNAME_MAXLEN) {
        fprintf(stderr, "Name is too long.");
        return -1;
    }
    char *label = NULL,
        *addr = strdup(name);
    int len, total = 0;
    while ((label = strsep(&addr, ".")) != NULL) {
        len = strlen(label);
        if (len > QNAME_LABELMAXLEN) {
            fprintf(stderr, "Label is too long");
            free(addr);
            return -1;
        }
        qname[total++] = len;
        strcat(&qname[total], label);
        total += len;
    }
    free(addr);
    return 1;
}

Resource *dns_createresource() {
    return calloc(sizeof(Resource), 1);
}

void dns_destroyresource(Resource *r) {
    free(r);
}
