
#include <libnet.h>

#define DNS_NAME_LENGTH 64
#define RECORD_BUFFER_SIZE 1024
#define NULL_PAYLOAD NULL
#define NULL_PAYLOAD_SIZE 0
typedef unsigned char uchar_t;

/*
 *	libnet_t* context
 *	char* errorBuffer
*/
struct Libnet {
	libnet_t* context;
	char* errorBuffer;
};
/*
 * uint32_t source
 * uint32_t destination 
 */
struct NetworkOrderedIPs {
	uint32_t source;
	uint32_t destination;
};

/**
 * 
	struct NetworkOrderedIPs networkOrderedIPs
	uint16_t sourcePort
	uint16_t destinationPort
	uint16_t queryID
*/
struct BaseRequestOptions {
	struct NetworkOrderedIPs networkOrderedIPs;
	uint16_t sourcePort;
	uint16_t destinationPort;
	uint16_t queryID;
};

struct IPv4HeaderOptions {
	struct Libnet libnet;
	uint16_t recordsLength;
	struct BaseRequestOptions base;
};

/*
 * struct Libnet libenet
 * uint16_t recordsLength
 * struct BaseRequestOptions
*/
struct UDPHeaderOptions {
	struct Libnet libnet;
	uint16_t recordsLength;
	struct BaseRequestOptions base;
};

/**
 * 
 * struct Libnet libnet;
 * 	u_int16_t resourceLength;
 * 	uint16_t queryID;
 *	uint16_t flags;
 *	uint16_t numberQuestions;
 *	uint16_t numberAnswerResourceRecords;
 * 	uint16_t authorityResourceRecord;
 *	uint16_t additionalRecords;
 * libnet_ptag_t ptag;
*/
struct DNSHeaderOptions {
	struct Libnet libnet;
	u_int16_t resourceLength;
	uint16_t queryID;
	uint16_t flags;
	uint16_t numberQuestions;
	uint16_t numberAnswerResourceRecords;
	uint16_t authorityResourceRecord;
	uint16_t additionalRecords;
	libnet_ptag_t ptag;
};

struct DNSQuestionFormatOptions {
	char* qname;
	uint16_t qtype;
	uint16_t qclass;
};

struct DNSQuestionRecordOptions {
	struct Libnet libnet;
	struct DNSQuestionFormatOptions formatOptions;
	libnet_ptag_t ptag;
};

struct QuestionRecord {
	libnet_ptag_t ptag;
	uint16_t questionSize;
};

struct DNSRequestHeadersOptions {
	struct Libnet libnet;
	struct BaseRequestOptions base;
	struct DNSHeaderOptions dnsHeader;
	struct UDPHeaderOptions udpHeader;
	struct IPv4HeaderOptions ipHeader;
	uint16_t recordsSize;
};

struct BaseRequestHeaders {
	libnet_ptag_t DNSHeaderPtag;
	libnet_ptag_t UDPHeaderPtag;
	libnet_ptag_t IPv4HeaderPtag;
};

struct BaseRequest {
	struct Libnet libnet;
	struct BaseRequestHeaders headers;
};


struct StringBaseRequestOptions {
	char* qname;
	char* sourceIP;
	char* destinationIP;
	struct BaseRequestOptions base;
};

struct DNSAnswerRecord {
	uint16_t recordSize;
	libnet_ptag_t ptag;
};

struct DNSAnswerRecordOptions {
	struct Libnet libnet;
	libnet_ptag_t ptag;
	char* qname;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
	char* rdata;
};
struct DNSQueryRequest {
	struct QuestionRecord questionRecord;
	struct BaseRequest base;
	struct DNSQuestionRecordOptions questionRecordOptions;
};

struct DNSAnswerRequest {
	struct BaseRequest base;
	struct DNSAnswerRecord answerRecord;
	struct QuestionRecord questionRecord;
	struct DNSHeaderOptions dnsHeaderOptions;
	struct DNSAnswerRecordOptions answerRecordOptions;
	struct DNSQuestionRecordOptions questionRecordOptions;
};
struct DNSAnswerRecordFormatOptions {
	struct Libnet libnet;
	uchar_t* buffer;
	struct DNSAnswerRecordOptions answer;
};