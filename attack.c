#include <libnet.h>
#include <assert.h>
#include <string.h>

#define DNS_NAME_LENGTH 64

int main(int argc, char* argv[]) {
    libnet_t* libnet;
    char libnetErrorBuffer[LIBNET_ERRBUF_SIZE];
    unsigned long dst_ip = 0;
    libnet = libnet_init(
        LIBNET_RAW4,                            /* injection type */
        NULL,                                   /* network interface */
        libnetErrorBuffer);                                /* error buffer */

    if (!libnet) {
        fprintf(stderr, "Could not initiate libnet: %s", libnetErrorBuffer);
        exit(EXIT_FAILURE);
    }

    char dnsName[DNS_NAME_LENGTH] = {'\0'} ;
    if (argc > 1) {
        if(strlen(argv[1]) >= DNS_NAME_LENGTH){
            fprintf(stderr, "Error domain name is too large, try something smaller than %d\n", DNS_NAME_LENGTH);
            exit(EXIT_FAILURE);
        }
        const char* res = strncpy(dnsName, argv[1], DNS_NAME_LENGTH);
        if(!res){
            fprintf(stderr, "Error copying dnsName.\n");
            exit(EXIT_FAILURE);
        }

    } else {
        strncpy(dnsName, "google.com", DNS_NAME_LENGTH);
    }

    dst_ip = libnet_name2addr4(libnet, dnsName, LIBNET_RESOLVE);

    if (dst_ip == -1) {
        fprintf(stderr, "Error fetching host name IPv4 address: %s", libnetErrorBuffer);
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "IPv4 Address: %ld\n", dst_ip);
    return 0;
}