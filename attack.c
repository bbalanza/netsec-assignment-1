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
	libnet_t* library;
	char* errorBuffer;
};

struct IPv4Options {
	uint16_t payloadSize;
	uint32_t sourceIP;
	uint32_t destinationIP;
};

struct UDPOptions {
	uint16_t payloadSize;
	uint16_t sourcePort;
	uint16_t destinationPort;
};

struct DNSOptions {
	u_int16_t payloadSize;
	char* payloadBuffer;
	uint16_t queryID;
};

struct PayloadOptions {
	char* payloadBuffer;
	char* subdomain;
	char* domain;
	char* root;
};

struct DNSQuestionPacketOptions {
	uint16_t payloadSize;
	char* payloadBuffer;
};

void 			destroyLibnet(struct Libnet libnet);
void 			parseArguments(int part, int argc, char* argv[]);
char 			size_tToChar(size_t size);
short 			parseOptions(int argc, char* argv[]);
uint16_t 		makePayload(struct PayloadOptions options);
uint32_t 		makeByteNumberedIP(struct Libnet libnet, char* name, int resolve);
struct Libnet 	makeLibnet();
libnet_ptag_t 	makeIPHeader(struct Libnet libnet, struct IPv4Options options);
libnet_ptag_t 	makeUDPHeader(struct Libnet libnet, struct UDPOptions options);
libnet_ptag_t 	makeDNSPacket(struct Libnet libnet, struct DNSOptions options);
libnet_ptag_t 	makeDNSQuestionPacket(struct Libnet libnet, struct DNSQuestionPacketOptions DNSQuestionPacketOptions);

void partOne(int argc, char* argv[]) {

}

uint32_t baitResolver(libnet_t* libnet, char* name, char* ip) {

}

char size_tToChar(size_t size) {
	return (char)(size & 0xFF);
}


int main(int argc, char* argv[]) {

	short part = parseOptions(argc, argv);
	struct Libnet libnet = makeLibnet();

	char* triboreResolverIP = "192.168.10.10"; /*Assignment makes use of hardcoded IP address for the nameserver*/
	uint32_t destinationIP = 0, sourceIP = 0;
	sourceIP = libnet_get_ipaddr4(libnet.library);
	destinationIP = makeByteNumberedIP(libnet, triboreResolverIP, LIBNET_DONT_RESOLVE);
	uint16_t sourcePort = 53, destinationPort = 53;
	libnet_ptag_t IPHeader, UDPHeader, DNSPacket, DNSQuestionPacket;
	char payloadBuffer[PAYLOAD_BUFFER_SIZE];
	char* subdomain = "vunet";
	char* domain = "vu";
	char* root = "nl";

	struct PayloadOptions PayloadOptions = { payloadBuffer, subdomain, domain, root };
	uint16_t payloadSize = makePayload(PayloadOptions);
	struct DNSQuestionPacketOptions DNSQuestionPacketOptions = { payloadSize, payloadBuffer };
	struct DNSOptions DNSOptions = { payloadSize, payloadBuffer, 0x1000 };
	struct UDPOptions UDPOptions = { payloadSize, sourcePort, destinationPort };
	struct IPv4Options IPOptions = { payloadSize, sourceIP, destinationIP };

	DNSQuestionPacket = makeDNSQuestionPacket(libnet, DNSQuestionPacketOptions);
	DNSPacket = makeDNSPacket(libnet, DNSOptions);
	UDPHeader = makeUDPHeader(libnet, UDPOptions);
	IPHeader = makeIPHeader(libnet, IPOptions);

	libnet_write(libnet.library);
	destroyLibnet(libnet);
	return 0;
}

libnet_ptag_t makeDNSPacket(struct Libnet libnet, struct DNSOptions options) {
	uint16_t FLAGS = 0x0100;
	u_int16_t NUMBER_QUESTIONS = 1; /* Might change in later parts.*/
	u_int16_t NUMBER_ANSWER_RR = 0;
	u_int16_t NUMBER_AUTHORITY_RR = 0;
	u_int16_t NUMBER_ADDITIONAL_RR = 0;
	libnet_ptag_t PTAG = 0;

	libnet_ptag_t DNSPacket = libnet_build_dnsv4(
		LIBNET_UDP_DNSV4_H,
		options.queryID,
		FLAGS,
		NUMBER_QUESTIONS,
		NUMBER_ANSWER_RR,
		NUMBER_AUTHORITY_RR,
		NUMBER_ADDITIONAL_RR,
		NULL_PAYLOAD,
		NULL_PAYLOAD_SIZE,
		libnet.library,
		PTAG
	);
	if (DNSPacket == -1) {
		fprintf(stderr, "Error: Could not create DNS packet. \nLibnet Error: %s", libnet_geterror(libnet.library));
		exit(EXIT_FAILURE);
	}
	return DNSPacket;
}

uint32_t makeByteNumberedIP(struct Libnet libnet, char* name, int resolve) {
	uint32_t byteOrderedIp;
	if ((byteOrderedIp = libnet_name2addr4(libnet.library, name, resolve)) == -1) {
		fprintf(stderr, "Error: Bad destination IP address.\n");
		exit(EXIT_FAILURE);
	}
	return byteOrderedIp;
}

uint16_t makePayload(struct PayloadOptions options) {
	uint16_t payloadSize = snprintf(options.payloadBuffer, sizeof(char) * PAYLOAD_BUFFER_SIZE, "%c%s%c%s%c%s%c%c%c%c%c",
		size_tToChar(strlen(options.subdomain)),
		options.subdomain,
		size_tToChar(strlen(options.domain)),
		options.domain,
		size_tToChar(strlen(options.root)),
		options.root,
		0x00,
		0x00, // QType
		0x01,
		0x00, // QClass
		0x01
	);
	return payloadSize;
}

libnet_ptag_t makeDNSQuestionPacket(struct Libnet libnet, struct DNSQuestionPacketOptions DNSQuestionPacketOptions) {
	libnet_ptag_t questionPacket = libnet_build_data(
		(uint8_t*)DNSQuestionPacketOptions.payloadBuffer,
		DNSQuestionPacketOptions.payloadSize,
		libnet.library,
		0
	);
	return questionPacket;
}

libnet_ptag_t makeUDPHeader(struct Libnet libnet, struct UDPOptions options) {
	uint16_t CHECKSUM = 0;
	uint16_t PTAG = 0;

	libnet_ptag_t UDPHeader = libnet_build_udp(
		options.sourcePort,
		options.destinationPort,
		LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + options.payloadSize,
		CHECKSUM,
		NULL_PAYLOAD,
		NULL_PAYLOAD_SIZE,
		libnet.library,
		PTAG
	);
	if (UDPHeader == -1) {
		fprintf(stderr, "Error could not create UDP header.\n Libnet Error: %s", libnet_geterror(libnet.library));
		exit(EXIT_FAILURE);
	}
}

libnet_ptag_t makeIPHeader(struct Libnet libnet, struct IPv4Options options) {
	uint8_t TYPE_OF_SERVICE = 0;
	uint16_t ID = 0;
	uint16_t FRAGMENTATION = 0;
	uint8_t TTL = 64;
	uint8_t PROTOCOL = IPPROTO_UDP;
	uint16_t CHECKSUM = 0;
	libnet_ptag_t PTAG = 0;

	libnet_ptag_t IPv4Header = libnet_build_ipv4(
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
		libnet.library,
		PTAG
	);
	if (IPv4Header == -1) {
		fprintf(stderr, "Error: Could not create IPv4 Header.\n Libnet Error: %s", libnet_geterror(libnet.library));
		exit(EXIT_FAILURE);
	}
	return IPv4Header;
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
	libnet.library = libnet_init(
		LIBNET_RAW4,
		"enp0s8",
		libnet.errorBuffer);

	if (!libnet.library) {
		fprintf(stderr, "Could not initiate libnet: %s\n", libnet.errorBuffer);
		exit(EXIT_FAILURE);
	}
	return libnet;
}

void destroyLibnet(struct Libnet libnet) {
	libnet_destroy(libnet.library);
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