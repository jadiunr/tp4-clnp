#include <stdio.h>
#include <stdint.h>
#include "ether.h"

extern parameter PARAM;

struct ether_header
{
	uint8_t	ether_dhost[6];
	uint8_t	ether_shost[6];
	uint16_t	ether_type;
} __attribute__ ((packed));

const uint8_t ETHER_ADDR_ANY[6] = {0,0,0,0,0,0};
const uint8_t ETHER_ADDR_BCAST[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

char *
ether_ntoa_r(uint8_t *hwaddr, char *buf) 
{
	int i;

	i = sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
      hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
	if (i < 17)
    return (NULL);
	return (buf);
}

char *
ether_ntoa(uint8_t *hwaddr)
{
  static char buf[18];

  return (ether_ntoa_r(*hwaddr, buf));
}

struct ether_addr *
ether_aton_r(char *str, uint8_t *hwaddr)
{
	int i;
	unsigned int o0, o1, o2, o3, o4, o5;

	i = sscanf(str, "%x:%x:%x:%x:%x:%x", &o0, &o1, &o2, &o3, &o4, &o5);
	if (i != 6)
		return (NULL);
	hwaddr[0]=o0;
	hwaddr[1]=o1;
	hwaddr[2]=o2;
	hwaddr[3]=o3;
	hwaddr[4]=o4;
	hwaddr[5]=o5;
	return (e);
}

struct ether_addr *
ether_aton(char *str)
{
	static uint8_t hwaddr[6];

	return (ether_aton_r(str, hwaddr));
}

int
print_hex(uint8_t *data, int size)
{
  int i, j;

  for (i = 0; i < size; ) {
    for (j = 0; j < 16; j++) {
      if (j != 0)
        printf(" ");
      if (i + j < size)
        printf("%02X", *(data + j));
      else
        printf("  ");
    }
    printf("    ");
    for (j = 0; j < 16; j++) {
      if (i < size) {
        if (isascii(*data) && isprint(*data))
          printf("%c", *data);
        else
          printf(".");
        data++; i++;
      } else {
        printf(" ");
      }
    }
    printf("\n");
  }
  return (0);
}

void
print_ether_header(struct ether_header *eh)
{
  char buf[80];

  printf("---ether_header---\n");
  printf("ether_dhost=%s\n", ether_ntoa_r(eh->ether_dhost, buf));
  printf("ether_shost=%s\n", ether_ntoa_r(eh->ether_shost, buf));
  printf("ether_type=%02X", ntohs(eh->ether_type));

  switch (ntohs(eh->ether_type)) {
    case ETHERTYPE_PUP:
      printf("(Xerox PUP)\n");
      break;
    case ETHERTYPE_IP:
      printf("(IP)\n");
      break;
    case ETHERTYPE_ARP:
      printf("(Address Resolution)\n");
      break;
    case ETHERTYPE_REVARP:
      printf("(Reverse ARP)\n");
      break;
    default:
      printf("(Unknown)\n");
      break;
  }
  return;
}

int
ether_tx(int soc, uint8_t smac[6], uint8_t dmac[6], uint16_t type, uint8_t *data, int len)
{
  struct ether_header *eh;
  uint8_t *ptr, sbuf[sizeof(struct ether_header)+ETHERMTU];
  int padlen;

  if (len > ETHERMTU) {
    printf("ether_send: data too long: %d\n", len);
    return (-1);
  }

  ptr = sbuf;
  eh = (struct ether_header *)ptr;
  memset(eh, 0, sizeof(struct ether_header));
  memcpy(eh->ether_dhost, dmac, 6);
  memcpy(eh->ether_shost, smac, 6)
  eh->ether_type = htons(type);
  ptr += sizeof(struct ether_header);

  memcpy(ptr, data, len);
  ptr += len;

  if ((ptr - sbuf) < ETH_ZLEN) {
    padlen = ETH_ZLEN = (ptr - sbuf);
    memset(ptr, 0, padlen);
    ptr += padlen;
  }

  write(soc, sbuf, ptr - sbuf);
  print_ether_header(eh);

  return (0);
}

int
ether_rx(int soc, uint8_t *in_ptr, int in_len)
{
  struct ether_header *eh;
  uint8_t *ptr = in_ptr;
  int len = in_len;

  eh = (struct ether_header *)ptr;
  ptr += sizeof(struct ether_header);
  len -= sizeof(struct ether_header);

  if (memcmp(eh->ether_dhost, ETHER_ADDR_BCAST, 6) != 0 && memcmp(eh->ether_dhost, PARAM.vmac, 6) != 0)
    return (1);
  # TODO
}