#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> // ETH_P_ALL
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct EtherCatFrameHeader {
  uint8_t destination[6];
  uint8_t source[6];
  uint16_t ethertype;
} __attribute__((packed));

typedef struct EtherCatDatagram {
  uint8_t datagram_header[10];
  uint8_t data[1486];
  uint16_t wkc;
} EtherCatDatagram;

uint8_t getEthercatCmd(EtherCatDatagram *ecd) {
  return ecd->datagram_header[0];
}

uint8_t getEthercatIdx(EtherCatDatagram *ecd) {
  return ecd->datagram_header[1];
}

uint16_t getEthercatLen(EtherCatDatagram *ecd) {
  return ecd->datagram_header[5] & 0b1111111111100000;
}

static inline uint64_t mac6_to_u64(const uint8_t mac[6]) {
  return ((uint64_t)mac[0] << 40) | ((uint64_t)mac[1] << 32) |
         ((uint64_t)mac[2] << 24) | ((uint64_t)mac[3] << 16) |
         ((uint64_t)mac[4] << 8) | (uint64_t)mac[5];
}

static void print_mac(const uint8_t mac[6]) {
  printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3],
         mac[4], mac[5]);
}

void parseFrame(uint8_t *buf, ssize_t len) {
  if (len < (ssize_t)sizeof(struct EtherCatFrameHeader)) {
    fprintf(stderr, "frame too short: %zd\n", len);
    return;
  }

  struct EtherCatFrameHeader hdr;
  memcpy(hdr.destination, buf + 0, 6);
  memcpy(hdr.source, buf + 6, 6);
  uint16_t ethertype_net = 0;
  memcpy(&ethertype_net, buf + 12, 2);
  uint16_t ethertype = ntohs(ethertype_net);
  size_t hdr_len = 14;
  hdr.ethertype = ethertype;

  const uint16_t ETHERTYPE_ETHERCAT = 0x88A4;
  printf("frame len=%zd, hdrlen=%zu, ethertype=0x%04x\n", len, hdr_len,
         hdr.ethertype);
  printf(" dst=");
  print_mac(hdr.destination);
  printf(" src=");
  print_mac(hdr.source);

  if (hdr.ethertype == ETHERTYPE_ETHERCAT) {
    printf(" EtherCAT frame detected; payload length=%zd\n", len - hdr_len);

    struct EtherCatDatagram ecd;
    memcpy(ecd.datagram_header, buf + hdr_len, 10);
    uint16_t len = getEthercatLen(&ecd);
    printf("EthercCAT DataGram Length %u", len);
    // memcpy(ecd.data, buf + 24, 1486);
    // memcpy(&ecd.wkc, buf + 24 + 1486, 2);
    // ecd.wkc = ntohs(ecd.wkc);

  } else {
    printf(" payload proto: 0x%04x, payload len=%zd\n", hdr.ethertype,
           len - hdr_len);
  }
  uint64_t dst_key = mac6_to_u64(hdr.destination);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
    return 1;
  }
  const char *ifname = argv[1];

  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ETHERCAT));
  if (sock < 0) {
    perror("socket");
    return 1;
  }

  // get interface index
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
  if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
    perror("SIOCGIFINDEX");
    close(sock);
    return 1;
  }
  int ifindex = ifr.ifr_ifindex;

  // bind to the interface
  struct sockaddr_ll sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifindex;
  sll.sll_protocol =
      htons(ETH_P_ETHERCAT); // or htons(ETH_P_IP) for only IPv4 frames

  if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    perror("bind");
    close(sock);
    return 1;
  }

  printf("Bound AF_PACKET socket to %s (ifindex=%d). Receiving...\n", ifname,
         ifindex);

  unsigned char buf[65536];

  while (1) {
    ssize_t len = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
    if (len < 0) {
      if (errno == EINTR)
        continue;
      perror("recvfrom");
      break;
    }
    printf("recv: %zd bytes\n", len);
    parseFrame(buf, len);
  }

  close(sock);
  return 0;
}