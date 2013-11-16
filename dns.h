#ifndef DNS_H
#define DNS_H

#include <inttypes.h>
#include <stdbool.h>

#define DNS_PORT_NUMBER_STR "53"
#define MESSAGE_MAXLEN 512
/* Header flags
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#define HEADER_QR_RESPONSE (0x1 << 15)
#define HEADER_OPCODE_STATUS (0x2 << 11)
#define HEADER_OPCODE_IQUERY (0x1 << 11)
#define HEADER_OPCODE_QUERY  (0x0) /* default opcode */
#define HEADER_AA (0x1 << 10)
#define HEADER_TC (0x1 << 9)
#define HEADER_RD (0x1 << 8)
#define HEADER_RA (0x1 << 7)
#define HEADER_RCODE_REFUSED (0x5)
#define HEADER_RCODE_NOTIMPL (0x4)
#define HEADER_RCODE_NAME    (0x3)
#define HEADER_RCODE_SERVER  (0x2)
#define HEADER_RCODE_FORMAT  (0x1)
/* QTYPE values */
#define QTYPE_A 1 /* a host address */
#define QTYPE_NS 2 /* an authoritative name server */
#define QTYPE_MD 3 /* a mail destination (Obsolete - use MX) */
#define QTYPE_MF 4 /* a mail forwarder (Obsolete - use MX) */
#define QTYPE_CNAME 5 /* the canonical name for an alias */
#define QTYPE_SOA 6 /* marks the start of a zone of authority */
#define QTYPE_MB 7 /* a mailbox domain name (EXPERIMENTAL) */
#define QTYPE_MG 8 /* a mail group member (EXPERIMENTAL) */
#define QTYPE_MR 9 /* a mail rename domain name (EXPERIMENTAL) */
#define QTYPE_NULL 10 /* a null RR (EXPERIMENTAL) */
#define QTYPE_WKS 11 /* a well known service description */
#define QTYPE_PTR 12 /* a domain name pointer */
#define QTYPE_HINFO 13 /* host information */
#define QTYPE_MINFO 14 /* mailbox or mail list information */
#define QTYPE_MX 15 /* mail exchange */
#define QTYPE_TXT 16 /* text strings */
#define QTYPE_AAAA 28 /* an IPv6 host addres host address (RFC 3596) */
/* QCLASS values */
#define QCLASS_IN 1 /* the Internet */
#define QCLASS_CS 2 /* the CSNET class (Obsolete) */
#define QCLASS_CH 3 /* the CHAOS class */
#define QCLASS_HS 4 /* Hesiod [Dyer 87] */
#define QCLASS_ANY 255 /* any class */

/* Header */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} Header;

typedef struct {
    char *qname;
    uint16_t qtype;
    uint16_t qclass;
} Question;

typedef struct {
    char *name;
    uint16_t type;
    uint16_t class;
    int32_t ttl;
    uint16_t rdlength;
    void *rdata;
} Resource;
#define QNAME_MAXLEN 254
#define QNAME_LABELMAXLEN 63

typedef struct {
    Header *header;
    Question *question;
    Resource **answer;
    Resource **authority;
    Resource **additional;
} Message;

Message *dns_createmessage();
Header *dns_createheader();
Question *dns_createquestion();
int dns_setqname(char *qname, const char *name);
Resource *dns_createresource();

void dns_destroymessage(Message *m);
void dns_destroyheader(Header *h);
void dns_destroyquestion(Question *q);

int dns_dumpmessage(Message *m, uint8_t *buffer);
int dns_dumpheader(Header *h, uint8_t *buffer);
int dns_dumpquestion(Question *q, uint8_t *buffer);

Message *dns_parsemessage(uint8_t *buffer);
Header *dns_parseheader(uint8_t *buffer, int *offset);
Question *dns_parsequestion(uint8_t *buffer, int *offset);
Resource *dns_parseresource(uint8_t *buffer, int *offset);

#endif
