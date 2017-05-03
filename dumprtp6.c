/*
 *  DUMPRTP6 - Next generation multicast RTP/UDP receiver
 *
 *  Copyright (C) 2009 Ondrej Caletka <o.caletka@sh.cvut.cz>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307	USA
 */

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <time.h>

#define max(a,b) ((a)>(b) ? (a):(b))
#define min(a,b) ((a)<(b) ? (a):(b))

#ifndef SOL_IP
#  define SOL_IP IPPROTO_IP
#endif
#ifndef SOL_IPV6
#  define SOL_IPV6 IPPROTO_IPV6
#endif

#ifndef HAVE_PROGRAM_INVOCATION_SHORT_NAME
char program_invocation_short_name[] = PACKAGE;
#endif

enum loglevel {
	LOG_FATAL = 0, /* Always shown */
	LOG_ERROR,     /* Could be silenced */
	LOG_INFO,      /* Default verbosity */
	LOG_DEBUG
};

/*** GLOBALS ***/
enum loglevel conf_verbosity = LOG_ERROR;
char *conf_interface = NULL;
char *conf_source = NULL;
char *conf_output = NULL;
int conf_udponly = 0;
int conf_family = 0;
char *conf_IP = NULL;
char *conf_port = NULL;

#define UDPBUFLEN 2000

/**
 * Logger function. Show the message if current verbosity is above
 * logged level.
 *
 * @param levem Message log level
 * @param format printf style format string
 * @returns Whatever printf returns
 */
int logger(enum loglevel level, const char *format, ...) {
	va_list ap, aq;
	char buf[50];
	time_t now_epoch;
	struct tm *now;
	int r = 0;
	if (conf_verbosity >= level) {
		va_start(ap, format);
		time(&now_epoch);
		now = localtime(&now_epoch);
		strftime(buf, 50, "%Y-%m-%d %H:%M:%S", now);
		fprintf(stderr, "%s ", buf);
		r=vfprintf(stderr,format, ap);
		va_end(ap);
	}
	return r;
}


void usage(FILE* f) {
	fprintf(f, 
PACKAGE " - Next generation RTP/UDP stream receiver\n"
"\n"
"Version " VERSION "\n"
"Copyright 2009 Ondrej Caletka <o.caletka@sh.cvut.cz>\n"
"\n"
"This program is free software; you can redistribute it and/or modify\n"
"it under the terms of the GNU General Public License version 2\n"
"as published by the Free Software Foundation.\n"
"\n"
"Usage: %s [options] <mulicast IP address> [port]\n"
"\n"
"Options:\n"
"\t-h --help --usage		Show this help\n"
"\t-V --version			Show program version\n"
"\t-v --verbose			Increase verbosity\n"
"\t-q --quiet			Report only fatal errors\n"
"\t-i --interface <ifname>	\tUse this interface\n"
"\t-s --source <ip or hostname> Get stream from this source only\n"
"\t-o --output <filename>	\tWrite to file rather than stdout\n"
"\t-u --udponly			Stream is UDP-only, not RTP/UDP\n"
"\t-4 --inet			Force IPv4\n"
"\t-6 --inet6			Force IPv6\n",
	program_invocation_short_name);
}



void parseCmdLine(int argc, char *argv[]) {
	static const struct option longopts[] = {
		{ "help",	no_argument,		NULL,	'h' },
		{ "usage",	no_argument,		NULL,	'h' },
		{ "quiet",	no_argument,		NULL,	'q' },
		{ "verbose",	no_argument,		NULL,	'v' },
		{ "version",	no_argument,		NULL,	'V' },
		{ "interface",	required_argument,	NULL,	'i' },
		{ "source",	required_argument,	NULL,	's' },
		{ "output",	required_argument,	NULL,	'o' },
		{ "udponly",	no_argument,		NULL,	'u' },
		{ "inet",	no_argument,		NULL,	'4' },
		{ "inet6",	no_argument,		NULL,	'6' },
		{ 0,		0,			0,	0   }
	};
	static const char shortopts[] = "hqvVi:s:o:u46";

	int option_index, opt;
	
	while ((opt = getopt_long(argc, argv, shortopts,
					longopts, &option_index)) != -1) {
		switch (opt) {
			case 0:
				break;
			case 'h':
				usage(stdout);
				exit(EXIT_SUCCESS);
				break;
			case 'q':
				conf_verbosity=0;
				break;
			case 'v':
				conf_verbosity++;
				break;
			case 'V':
				puts(PACKAGE " " VERSION);
				exit(EXIT_SUCCESS);
				break;
			case 'i':
				conf_interface = strdup(optarg);
				break;
			case 'o':
				conf_output = strdup(optarg);
				break;
			case 's':
				conf_source = strdup(optarg);
				break;
			case 'u':
				conf_udponly = 1;
				break;
			case '4':
				conf_family = AF_INET;
				break;
			case '6':
				conf_family = AF_INET6;
				break;
			default:
				usage(stderr);
				exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc) {
		logger(LOG_FATAL, "Error, no IP address found.\n");
		usage(stderr);
		exit(EXIT_FAILURE);
	}
	conf_IP = strdup(argv[optind]);

	if (++optind < argc) {
		conf_port = strdup(argv[optind]);
	} else {
		conf_port = strdup("1234");
	}
}

/*
 *Fallback to protocol-dependent multicast join API
 */
int fallback(int sock, int ssm, void *group_request) {
	struct sockaddr_storage group;
	int ifid;
	struct ip_mreq im;
	struct ipv6_mreq im6;
	struct in_addr iface = { .s_addr = INADDR_ANY };
	int r;

	logger(LOG_ERROR, "Falling back to old API.\n");
	if (ssm) {
		group = ((struct group_source_req *)group_request)->gsr_group;
		ifid = ((struct group_source_req *)group_request)->gsr_interface;
		logger(LOG_ERROR, " - SSM not supported here.\n");
	} else {
		group = ((struct group_req *)group_request)->gr_group;
		ifid = ((struct group_req *)group_request)->gr_interface;
	}

	switch (group.ss_family) {
		case AF_INET:
			im.imr_multiaddr = ((struct sockaddr_in*)&group)->sin_addr;
			im.imr_interface = iface;
			r = setsockopt(sock, SOL_IP, IP_ADD_MEMBERSHIP,
						&im, sizeof(im));
			if (r) {
				logger(LOG_FATAL, "Fallback IPv4 join failed: %s\n",
						strerror(errno));
				return -1;
			}
			if (ifid) {
				logger(LOG_ERROR, " - Iface not supported here.\n");
			}
			return 0;
			break;

		case AF_INET6:
			im6.ipv6mr_multiaddr = ((struct sockaddr_in6*)&group)->sin6_addr;
			im6.ipv6mr_interface = ifid;
			r = setsockopt(sock, SOL_IPV6, IPV6_JOIN_GROUP,
						&im6, sizeof(im6));
			if (r) {
				logger(LOG_FATAL, "Fallback IPv6 join failed: %s\n",
						strerror(errno));
				return -1;
			}
			return 0;
			break;

		default:
			logger(LOG_FATAL, "Address family not supported!\n");
			return -1;
	}
}

int main(int argc, char *argv[]) {

	struct addrinfo hints, *res, *src=NULL;
	int r;
	int sock, output_fd;
	union {
		struct group_req gr;
		struct group_source_req gsr;
	} gr;
	int ifid, level;
	int ssm = 0;
	int on = 1;
	int first = 1;

	parseCmdLine(argc, argv);


	if (conf_output) {
		output_fd = open(conf_output, O_WRONLY | O_CREAT | O_TRUNC, 0755);
		free(conf_output);
		conf_output = NULL;
	} else {
		output_fd = fileno(stdout);
		if (isatty(output_fd)) {
			logger(LOG_ERROR, "Output should be redirected. Not writing any data.\n");
			output_fd = open("/dev/null", O_WRONLY);
		}
	}
	if (output_fd < 0) {
		logger(LOG_FATAL, "Cannot open output file: %s\n",
				strerror(errno));
		exit(EXIT_FAILURE);
	}


	memset(&hints, 0, sizeof(hints));
	hints.ai_family = conf_family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	r = getaddrinfo(conf_IP, conf_port, &hints, &res);
	free(conf_IP); conf_IP=NULL;
	free(conf_port); conf_port=NULL;
	if (r) {
		logger(LOG_FATAL, "Getaddrinfo failed: %s\n",
				gai_strerror(r));
		exit(EXIT_FAILURE);
	}
	if (res->ai_next != NULL) {
		logger(LOG_ERROR, "The multicast address is ambiguous!\n");
	}

	sock = socket(res->ai_family, res->ai_socktype, 
	              res->ai_protocol);
	r = setsockopt(sock, SOL_SOCKET,
	               SO_REUSEADDR, &on, sizeof(on));
	if (r) {
		logger(LOG_ERROR, "SO_REUSEADDR "
		"failed: %s\n", strerror(errno));
	}
	r = bind(sock,(struct sockaddr *) res->ai_addr, res->ai_addrlen);
	if (r) {
		logger(LOG_FATAL, "Cannot bind: %s\n",
		       strerror(errno));
		exit(EXIT_FAILURE);
	}


	/** SSM Case */
	if (conf_source) {
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = conf_family;
		r = getaddrinfo(conf_source, NULL, &hints, &src);
		free(conf_source); conf_source=NULL;
		if (r) {
			logger(LOG_FATAL, "Source getaddrinfo failed: %s. Ignoring.\n",
					gai_strerror(r));
			ssm = 0;
		} else {
			if (res->ai_next != NULL) {
				logger(LOG_ERROR,
				"The source address is ambiguous!\n");
			}
			memcpy(&(gr.gsr.gsr_source), src->ai_addr,
				min(sizeof(gr.gsr.gsr_source), src->ai_addrlen));
			ssm = 1;
			freeaddrinfo(src); src=NULL;
		}
	}

	/** Interface Case */
	if (conf_interface) {
		ifid = if_nametoindex(conf_interface);
		if (ifid == 0) {
			logger(LOG_ERROR, "Interface %s not found. Ignoring\n",
					conf_interface);
		}
		free(conf_interface); conf_interface=NULL;
	} else {
		ifid = 0;
	}

	switch (res->ai_family) {
		case AF_INET:
			level = SOL_IP;
			break;
			
		case AF_INET6:
			level = SOL_IPV6;
			if ( ((const struct sockaddr_in6 *)
				(res->ai_addr))->sin6_scope_id != 0) {
				if (ifid != 0) {
					logger(LOG_ERROR, 
						"Interface id overriden "
						"by scoped IPv6 address.\n");
				}
				ifid = ((const struct sockaddr_in6 *)
						(res->ai_addr))->sin6_scope_id;
			}
			break;
		default:
			logger(LOG_ERROR, "Address family does not support mcast.\n");
			exit(EXIT_FAILURE);
	}			 

	if (ssm) {
		memcpy(&(gr.gsr.gsr_group), res->ai_addr,
			min(sizeof(gr.gsr.gsr_group), res->ai_addrlen));
		gr.gsr.gsr_interface = ifid;
		r = setsockopt(sock, level,
			MCAST_JOIN_SOURCE_GROUP, &(gr.gsr), sizeof(gr.gsr));
	} else {
		memcpy(&(gr.gr.gr_group), res->ai_addr,
			min(sizeof(gr.gr.gr_group), res->ai_addrlen));
		gr.gr.gr_interface = ifid;
		r = setsockopt(sock, level,
			MCAST_JOIN_GROUP, &(gr.gr), sizeof(gr.gr));
	}

	if (r) {
		logger(LOG_ERROR, "Cannot join mcast group: %s\n",
				strerror(errno));
		/*Fallback to protocol-specific API*/
		if (fallback(sock, ssm, ssm? (void*)&(gr.gsr):(void*)&(gr.gr))){
			logger(LOG_FATAL, "Fallback failed.\n");
			exit(EXIT_FAILURE);
		}
		logger(LOG_ERROR, "Fallback succeded.\n");
	}
	freeaddrinfo(res); res= NULL;

	/** Joined. Let's forward traffic. */
	logger(LOG_DEBUG, "Joined. Waiting for data...\n");

	while(1) {
		uint8_t buf[UDPBUFLEN];
		int payloadstart, payloadlength;
		uint16_t seqn, oldseqn;

		r = recv(sock, buf, sizeof(buf), 0);
		if (r < 0){
			logger(LOG_FATAL,"Recv() failed: %s\n",
			       strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (first) {
			logger(LOG_INFO, "First packet received. Good.\n");
		}
		if (first && !conf_udponly &&
			(r < 12 || (buf[0]&0xC0) != 0x80)) {
			logger(LOG_ERROR, "First packet is not RTP, "
					"switching to UDP mode.\n");
			conf_udponly = 1;
		}
		if (!conf_udponly) {
			if (r < 12 || (buf[0]&0xC0) != 0x80) { 
				/*malformed RTP/UDP/IP packet*/
				logger(LOG_INFO,"Malformed RTP packet received\n");
				continue;
			}
	
			payloadstart = 12; /* basic RTP header length */
			if (buf[0]&0x0F) {
				payloadstart += (buf[0]&0x0F) * 4; /*CRSC headers*/
				logger(LOG_DEBUG, "CRSC header found\n");
			}
			if (buf[0]&0x10) { /*Extension header*/
				payloadstart += 4 + 4*ntohs(*((uint16_t *)(buf+payloadstart+2)));
				logger(LOG_DEBUG, "Extension header found\n");
			}
			payloadlength = r - payloadstart;
			if (buf[0]&0x20) { /*Padding*/
				payloadlength -= buf[r];
				logger(LOG_DEBUG, "Padding found\n");
				/*last octet indicate padding length*/
			}
			if(payloadlength<0) {
				logger(LOG_INFO,"Malformed RTP packet received\n");
				continue;
			}
			seqn = ntohs(*((uint16_t *)(buf+2)));
			if (!first && seqn==oldseqn) {
				logger(LOG_INFO,"Duplicated RTP packet "
					"received (seqn %d)\n", seqn);
				continue;
			}
			if (!first && (seqn != ((oldseqn+1)&0xFFFF))) {
				logger(LOG_INFO,"Congestion - expected %d, "
					"received %d\n", (oldseqn+1)&0xFFFF, seqn);
			}
			oldseqn=seqn;
		} else {
			payloadstart = 0;
			payloadlength = r;
		}

		first=0;
		while (payloadlength>0) {
			r = write(output_fd, buf+payloadstart, payloadlength);
			if (r<0) {
				logger(LOG_FATAL, "Write failed: %s\n",
						strerror(errno));
				exit(EXIT_FAILURE);
			}
			if (r != payloadlength) {
				logger(LOG_DEBUG, "Not all data written -"
				       " requested %d, written %d\n",
				       payloadlength, r);
			}
			payloadstart += r;
			payloadlength -= r;
		}
	}

	/* should never reach here */
	return 0;
}








