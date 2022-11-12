void 						parseArguments(int part, int argc, char* argv[]);
void 						uint16ToChars(uchar_t* buffer, uint16_t uint);
void 						uint32ToChars(uchar_t* buffer, uint32_t uint32);
char 						uint32toOctateChar(uint32_t uint32);
char 						uint8toOctateChar(uint8_t uint8);
uint16_t 					makeDomain(char* buffer, char* domainString);
uint16_t 					uint16tono16(uint16_t uint);
short 						parseOptions(int argc, char* argv[]);
uint32_t 					uint32tono32(uint32_t uint32);
struct NetworkOrderedIPs 	parseIPs(struct Libnet libnet, char* sourceIPString, char* destinationIPString);

char uint8toOctateChar(uint8_t uint8) {
	return (char)(uint8 & 0xFF);
}
char uint32toOctateChar(uint32_t uint32) {
	return (char)(uint32 & 0xFF);
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

