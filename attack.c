#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdint.h>
#include <libnet.h>

#define DNS_NAME_LENGTH 64
#define PAYLOAD_BUFFER_SIZE 1024
#define NULL_PAYLOAD NULL
#define NULL_PAYLOAD_SIZE 0

struct Libnet {
	libnet_t* context;
	char* errorBuffer;
};

struct IPv4HeaderOptions {
	uint16_t payloadSize;
	uint32_t sourceIP;
	uint32_t destinationIP;
};

struct UDPHeaderOptions {
	uint16_t payloadSize;
	uint16_t sourcePort;
	uint16_t destinationPort;
};

struct DNSHeaderOptions {
	u_int16_t payloadSize;
	uint16_t queryID;
};

struct DNSQuestionFormatOptions {
	char* qname;
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


struct DNSRequestHeadersOptions {
	struct Libnet libnet;
	uint16_t queryID;
	uint16_t sourcePort;
	uint16_t destinationPort;
	uint32_t sourceIP;
	uint32_t destinationIP;
	uint16_t recordsSize;
};

struct DNSBaseRequest {
	struct Libnet libnet;
	struct DNSRequestHeaders headers;
};

struct DNSQnameRequest {
	struct DNSQuestionRecord DNSQuestionRecord;
	struct DNSBaseRequest base;
};

struct DNSQnameRequestOptions {
	char* source;
	char* destination;
	char* qname;
};

struct DNSAnswerRecord {
	uint16_t recordSize;
	libnet_ptag_t ptag;
};

struct DNSAnswerRecordOptions {
	char* buffer;
	char* qname;
};

void 						destroyLibnetContext(struct Libnet libnet);
void 						parseArguments(int part, int argc, char* argv[]);
char 						uint32toOctateChar(uint32_t uint32);
char 						uint8toOctateChar(uint8_t uint8);
uint16_t 						makeDomain(char* buffer, char* domainString);
short 						parseOptions(int argc, char* argv[]);
uint16_t 					formatDNSQuestion(char* DNSQuestionBuffer, struct DNSQuestionFormatOptions options);
uint16_t					makeDomain(char* buffer, char* domainString);
uint32_t 					makeByteNumberedIP(struct Libnet libnet, char* name, int resolve);
struct Libnet 				makeLibnet();
libnet_ptag_t 				makeIPHeader(struct Libnet libnet, struct IPv4HeaderOptions options);
libnet_ptag_t 				makeUDPHeader(struct Libnet libnet, struct UDPHeaderOptions options);
libnet_ptag_t 				makeDNSHeader(struct Libnet libnet, struct DNSHeaderOptions options);
struct DNSRequestHeaders	makeDNSRequestHeaders(struct DNSRequestHeadersOptions options);
struct DNSQnameRequest 		makeDNSQnameQuery(struct DNSQnameRequestOptions options);
struct DNSQuestionRecord 	makeDNSQuestionRecord(struct DNSQuestionRecordOptions options);
struct DNSAnswerRecord 		makeDNSAnswerRecord(struct DNSAnswerRecordOptions options);


uint16_t makeDomain(char* buffer, char* domainString) {
	char* iter = domainString, * labelStart = domainString;
	char* bufferIter = buffer;
	uint32_t labelLength, domainLength = 0;
	while (1) {
		if (*iter == '.' || *iter == '\0') {
			char labelLengthAsChar = uint32toOctateChar(labelLength);
			memcpy(bufferIter, &labelLengthAsChar, sizeof(labelLengthAsChar));
			bufferIter += sizeof(labelLengthAsChar);

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
}

struct DNSAnswerRecord makeDNSAnswerRecord(struct DNSAnswerRecordOptions options) {

}

void partOne(int argc, char* argv[]) {

}

void baitResolver(char* sourceIP, char* destinationIP, char* qname) {
	struct DNSQnameRequestOptions DNSQnameRequestOptions = { sourceIP, destinationIP, qname };
	struct DNSQnameRequest QNameQuery = makeDNSQnameQuery(DNSQnameRequestOptions);
	libnet_write(QNameQuery.base.libnet.context);
	destroyLibnetContext(QNameQuery.base.libnet);
}

char uint8toOctateChar(uint8_t uint8) {
	return (char)(uint8 & 0xFF);
}
char uint32toOctateChar(uint32_t uint32) {
	return (char)(uint32 & 0xFF);
}


int main(int argc, char* argv[]) {

	short part = parseOptions(argc, argv);
	baitResolver(NULL, "192.168.10.10", NULL);
	return 0;
}

libnet_ptag_t makeDNSHeader(struct Libnet libnet, struct DNSHeaderOptions options) {
	uint16_t FLAGS = 0x0100;
	u_int16_t NUMBER_QUESTIONS = 1; /* Might change in later parts.*/
	u_int16_t NUMBER_ANSWER_RR = 0;
	u_int16_t NUMBER_AUTHORITY_RR = 0;
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
		libnet.context,
		PTAG
	);
	if (PTAG == -1) {
		fprintf(stderr, "Error: Could not create DNS header. \nLibnet Error: %s", libnet_geterror(libnet.context));
		exit(EXIT_FAILURE);
	}
	return PTAG;
}

struct DNSRequestHeaders makeDNSRequestHeaders(struct DNSRequestHeadersOptions options) {

	struct DNSRequestHeaders headers;
	struct DNSHeaderOptions DNSHeaderOptions = { options.recordsSize, options.queryID };
	struct UDPHeaderOptions UDPHeaderOptions = { options.recordsSize, options.sourcePort, options.destinationPort };
	struct IPv4HeaderOptions IPOptions = { options.recordsSize, options.sourceIP, options.destinationIP };

	headers.DNSHeaderPtag = makeDNSHeader(options.libnet, DNSHeaderOptions);
	headers.UDPHeaderPtag = makeUDPHeader(options.libnet, UDPHeaderOptions);
	headers.IPv4HeaderPtag = makeIPHeader(options.libnet, IPOptions);

}

struct DNSQnameRequest makeDNSQnameQuery(struct DNSQnameRequestOptions options) {

	struct DNSQnameRequest query;
	query.base.libnet = makeLibnet();

	uint32_t sourceIP, destinationIP = 0;
	if (options.source == NULL) {
		sourceIP = libnet_get_ipaddr4(query.base.libnet.context);
	}
	else {
		sourceIP = makeByteNumberedIP(query.base.libnet, options.source, LIBNET_DONT_RESOLVE);
	}

	destinationIP = makeByteNumberedIP(query.base.libnet, options.destination, LIBNET_DONT_RESOLVE);


	// This is hardcoded for now, but will change
	uint16_t sourcePort = 53, destinationPort = 53, queryID = 0x1000; /* Passed as argument.*/
	char* qname = "vunet.vu.nl";

	struct DNSQuestionFormatOptions DNSQuestionFormatOptions = { qname };
	struct DNSQuestionRecordOptions DNSQuestionRecordOptions = { query.base.libnet, DNSQuestionFormatOptions };
	query.DNSQuestionRecord = makeDNSQuestionRecord(DNSQuestionRecordOptions);

	struct DNSRequestHeadersOptions requestHeadersOptions;
	requestHeadersOptions.libnet = query.base.libnet;
	requestHeadersOptions.queryID = queryID;
	requestHeadersOptions.sourceIP = sourceIP;
	requestHeadersOptions.destinationIP = destinationIP;
	requestHeadersOptions.sourcePort = sourcePort;
	requestHeadersOptions.destinationPort = destinationPort;
	requestHeadersOptions.recordsSize = query.DNSQuestionRecord.questionSize;

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
	char QType[2] = { 0x00, 0x01 };
	char QClass[2] = { 0x00, 0x01 };

	memcpy(DNSQuestionBuffer + questionSize, &QType, sizeof QType);
	questionSize += sizeof QType;
	memcpy(DNSQuestionBuffer + questionSize, &QClass, sizeof QClass);
	questionSize += sizeof QClass;
	return questionSize;

}

struct DNSQuestionRecord makeDNSQuestionRecord(struct DNSQuestionRecordOptions options) {
	char questionBuffer[PAYLOAD_BUFFER_SIZE];
	uint16_t questionSize = formatDNSQuestion(questionBuffer, options.formatOptions);
	libnet_ptag_t libnet_ptag = libnet_build_data(
		(uint8_t*)questionBuffer,
		questionSize,
		libnet.context,
		0
	);
	if (libnet_ptag == -1) {
		fprintf(stderr, "Error could not create DNS question record..\n Libnet Error: %s", libnet_geterror(libnet.context));
		exit(EXIT_FAILURE);
	}
	return (struct DNSQuestionRecord) { libnet_ptag, questionSize };
}

libnet_ptag_t makeUDPHeader(struct Libnet libnet, struct UDPHeaderOptions options) {
	uint16_t CHECKSUM = 0;
	uint16_t PTAG = 0;

	libnet_ptag_t libnet_ptag = libnet_build_udp(
		options.sourcePort,
		options.destinationPort,
		LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + options.payloadSize,
		CHECKSUM,
		NULL_PAYLOAD,
		NULL_PAYLOAD_SIZE,
		libnet.context,
		PTAG
	);
	if (libnet_ptag == -1) {
		fprintf(stderr, "Error could not create UDP header.\n Libnet Error: %s", libnet_geterror(libnet.context));
		exit(EXIT_FAILURE);
	}
}

libnet_ptag_t makeIPHeader(struct Libnet libnet, struct IPv4HeaderOptions options) {
	uint8_t TYPE_OF_SERVICE = 0;
	uint16_t ID = 0;
	uint16_t FRAGMENTATION = 0;
	uint8_t TTL = 64;
	uint8_t PROTOCOL = IPPROTO_UDP;
	uint16_t CHECKSUM = 0;
	libnet_ptag_t PTAG = 0;

	libnet_ptag_t libnet_ptag = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + options.payloadSize,
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
		libnet.context,
		PTAG
	);
	if (libnet_ptag == -1) {
		fprintf(stderr, "Error: Could not create IPv4 Header.\n Libnet Error: %s", libnet_geterror(libnet.context));
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