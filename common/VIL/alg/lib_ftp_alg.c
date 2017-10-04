/*
// Copyright (c) 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <app.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_table_lpm.h>
#include <rte_table_hash.h>
#include <rte_pipeline.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include "pipeline_cgnapt_common.h"
#include "pipeline_actions_common.h"
#include "pipeline_cgnapt_be.h"
#include "hash_func.h"
#include "lib_ftp_alg.h"
#include "vnf_common.h"
#include "pipeline_common_be.h"
#include "rte_ct_tcp.h"
#include "rte_cnxn_tracking.h"
#define ALG_DEBUG 1

#if 1
extern uint8_t
rte_ct_create_cnxn_hashkey(
	uint32_t *src_addr,
	uint32_t *dst_addr,
	uint16_t src_port,
	uint16_t dst_port,
	uint8_t proto,
	uint32_t *key,
	uint8_t type);
#endif

struct rte_mbuf *lib_alg_pkt;
enum {PRIVATE, PUBLIC};
struct rte_hash_parameters ftp_alg_hash_params = {
	.name = "FTP ALG",
	.entries = 1024,
	.reserved = 0,
	.key_len = sizeof(struct ftp_alg_key),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
};

struct rte_hash *ftp_alg_hash_handle;

/**
 * ftp_alg Init function
 */
void lib_ftp_alg_init(void)
{
printf("NAT FTP ALG initialization ...\n");

	/* FTP ALG hash table initialization */

	ftp_alg_hash_handle = rte_hash_create(&ftp_alg_hash_params);

	#ifdef ALGDBG
	if (ftp_alg_hash_handle == NULL)
		printf("FTP ALG rte_hash_create failed ...\n");
	else
		printf("ftp_alg_hash_table %p\n\n",
			(void *)ftp_alg_hash_handle);

	#endif
}

/*
 * ftp_alg table retreive function
 * Input - alg key
 * Output - Entry
 */

struct ftp_alg_table_entry *retrieve_ftp_alg_entry(struct ftp_alg_key alg_key)
{
	struct ftp_alg_table_entry *ret_alg_data = NULL;
	alg_key.filler1 = 0;
	alg_key.filler2 = 0;

	int ret = rte_hash_lookup_data(ftp_alg_hash_handle, &alg_key,
							 (void **)&ret_alg_data);
	if (ret < 0) {
		#ifdef ALGDBG
		printf("alg-hash lookup failed ret %d, EINVAL %d, ENOENT %d\n",
					 ret, EINVAL, ENOENT);
		#endif
	} else {
		return ret_alg_data;
	}

	return NULL;
}

/*
 * ftp_alg table entry delete
 * Input - ipaddress, portid
 * Output - sucess or failure
 */
static int remove_ftp_alg_entry(uint32_t ipaddr, uint8_t portid)
{

	/* need to lock here if multi-threaded... */
	/* rte_hash_del_key is not thread safe */
	struct ftp_alg_key alg_key;
	alg_key.l4port = rte_bswap16(portid);
	alg_key.ip_address = rte_bswap32(ipaddr);
	alg_key.filler1 = 0;
	alg_key.filler2 = 0;

	#ifdef ALGDBG
		printf("remove_alg_entry ip %x, port %d\n", alg_key.ip_address,
					 alg_key.l4port);
	#endif
	return rte_hash_del_key(ftp_alg_hash_handle, &alg_key);
}
/*
 * ftp_alg table entry add
 * Input - ipaddress, portid
 * Output - sucess or failure
 */
void
populate_ftp_alg_entry(uint32_t ipaddr, uint8_t portid)
{
	/* need to lock here if multi-threaded */
	/* rte_hash_add_key_data is not thread safe */
	struct ftp_alg_key alg_key;
	alg_key.l4port = rte_bswap16(portid);
	//arp_key.ip = rte_bswap32(ipaddr);
	alg_key.ip_address = rte_bswap32(ipaddr);
	alg_key.filler1 = 0;
	alg_key.filler2 = 0;


	//lib_arp_populate_called++;

	#ifdef ALGDBG
	printf("populate_ftp_alg_entry ip %x, port %d\n", alg_key.ip_address,
					 alg_key.l4port);
	#endif

	struct ftp_alg_table_entry *new_alg_data =
		retrieve_ftp_alg_entry(alg_key);
	if (new_alg_data) {
		#ifdef ALGDBG
		printf("alg_entry exists ip%x, port %d\n", alg_key.ip_address,
				alg_key.l4port);
		#endif
		//lib_arp_duplicate_found++;
		return;
	}
	new_alg_data = (struct ftp_alg_table_entry *)
			malloc(sizeof(struct ftp_alg_table_entry));

	if (!new_alg_data) {
		printf("new_alg_data could not be allocated\n");
		return;
	}

	//new_alg_data->status = INCOMPLETE;
	new_alg_data->l4port = rte_bswap16(portid);
	new_alg_data->ip_address = rte_bswap32(ipaddr);
	rte_hash_add_key_data(ftp_alg_hash_handle, &alg_key, new_alg_data);

	#ifdef ALGDBG
		// print entire hash table
		printf
				("\tALG: table update - ip=%d.%d.%d.%d  on port=%d\n",
				 (alg_key.ip_address >> 24),
				 ((alg_key.ip_address & 0x00ff0000) >> 16),
				 ((alg_key.ip_address & 0x0000ff00) >> 8),
				 ((alg_key.ip_address & 0x000000ff)), portid);
		/* print_arp_table(); */
		puts("");
	#endif
}

/*
 * ftp_alg payload modification for PORT and PASV command
 * Input - cgnapt table entry - for taking the public /translated ip/port ,
 * incoming PORT/PASV string, Session type - PORT or PASV
 * Output - Translated string
 */
int ftp_alg_modify_payload(
	struct cgnapt_table_entry *egress_entry,
	char *port_string,
	char *port_string_translated, int ftp_session_type)
{
	uint32_t transport_ip;
	uint16_t transport_port;
	uint16_t tmp1, tmp2, tmp3, tmp4, tmp5, tmp6;
	uint16_t new_port_string_length;

	uint8_t *bptr_public_address;

	transport_ip = egress_entry->data.pub_ip;
	transport_port = egress_entry->data.pub_port;
	tmp5 = (uint16_t) (transport_port/0x100);
	tmp6 = (uint16_t) (transport_port % 0x100);

	transport_ip = rte_bswap32(transport_ip);

	bptr_public_address = (uint8_t *) &transport_ip;

	tmp4 = bptr_public_address[3];
	tmp3 = bptr_public_address[2];
	tmp2 = bptr_public_address[1];
	tmp1 = bptr_public_address[0];

	if (ftp_session_type == 1)
		sprintf(port_string_translated, FTP_PASV_PARAMETER_STRING,
			FTP_PASV_RETURN_CODE, tmp1, tmp2, tmp3, tmp4,
			tmp5, tmp6);
	else
		sprintf(port_string_translated, FTP_PORT_PARAMETER_STRING,
			tmp1, tmp2, tmp3, tmp4, tmp5, tmp6);
	#ifdef ALGDBG
	printf("FTP ALG: FTP new string: Len:%d %s\n",
			(uint16_t) strlen(port_string_translated)-2,
			port_string_translated);

	printf("FTP non translated PASV string: Len:%d, %s\n",
		(uint16_t)strlen(port_string)-2, port_string);
		printf("old strlen:%d  new strlen:%d\n",
		(int)strlen(port_string),
		(int)strlen(port_string_translated));
	#endif

	return(new_port_string_length =
		(uint16_t) strlen(port_string_translated));
}

/*
 * ftp_alg modify packet len (due to change in len of FTP payload )
 * Input - pkt
 * Output - Length append /Trimmed Pkt
**/
static inline void ftp_alg_modify_pkt_len(struct rte_mbuf *pkt)
{
	uint16_t pkt_length = 0;
	int ip_hdr_size_bytes = rte_ct_get_IP_hdr_size(pkt);
	void *iphdr = RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);

	if (ip_hdr_size_bytes == IPv4_HEADER_SIZE) {
		struct ipv4_hdr *ihdr4 = (struct ipv4_hdr *)iphdr;
		pkt_length = rte_bswap16(ihdr4->total_length) + ETH_HDR_SIZE;
	} else if (ip_hdr_size_bytes == IPv6_HEADER_SIZE) {
		struct ipv6_hdr *ihdr6 = (struct ipv6_hdr *)iphdr;
		pkt_length = rte_bswap16(ihdr6->payload_len) +
			IPv6_HEADER_SIZE + ETH_HDR_SIZE;
	}

	uint16_t mbuf_pkt_length = rte_pktmbuf_pkt_len(pkt);

	if (pkt_length == mbuf_pkt_length)
		return;

	if (pkt_length < mbuf_pkt_length) {
		rte_pktmbuf_trim(pkt, mbuf_pkt_length - pkt_length);
		return;
	}

	/* pkt_length > mbuf_pkt_length */
	rte_pktmbuf_append(pkt, pkt_length - mbuf_pkt_length);
}

/*
 * ftp_alg IP HDR size calculation
 * Input - pkt
 * Output - Length of IP HDR
 */

/* same as rte_ct_get_IP_hdr_size()*/
uint16_t ftp_alg_get_IP_hdr_size(struct rte_mbuf *pkt)
{
	/* NOTE: Only supporting IP headers with no options at this time
	* so header is fixed size
	*/

	uint8_t hdr_chk = RTE_MBUF_METADATA_UINT8(pkt, IP_START);
	hdr_chk = hdr_chk >> 4;

	if (hdr_chk == IP_VERSION_4)
		return IPv4_HEADER_SIZE;
	else if (hdr_chk == IP_VERSION_6)
		return IPv6_HEADER_SIZE;
	else            /* Not IPv4 header with no options, return negative. */
		return -1;

}

/*
 * ftp_alg checksum re-computing due to change in payload , uses rte function,
 * if HW Checksum is supported s/w checksum will be disabled
 * Input - IP HDR and TCP HDR
 * Output - Length of IP HDR
 */
static void ftp_alg_compute_checksums(
	void *i_hdr,
	struct tcp_hdr *t_hdr)
/* same as rte_synproxy_compute_checksums*/
{
	/*
	* calculate IP and TCP checksums.
	* Note that both checksum routines require
	* checksum fields to be set to zero, and the the checksum is in the
	* correct byte order, so no rte_bswap16 is required.
	*/

	int8_t hdr_chk = rte_ct_ipversion(i_hdr);
	t_hdr->cksum = 0;

	if (hdr_chk == IP_VERSION_4) {
		struct ipv4_hdr *i4_hdr = (struct ipv4_hdr *)i_hdr;
		i4_hdr->hdr_checksum = 0;
		t_hdr->cksum = 0;
		t_hdr->cksum = rte_ipv4_udptcp_cksum(i4_hdr, t_hdr);

		#ifdef ALGDBG
		printf("cksum %x\n", rte_bswap32(t_hdr->cksum));
		#endif

		i4_hdr->hdr_checksum = rte_ipv4_cksum(i4_hdr);
	} else if (hdr_chk == IP_VERSION_6) {
		struct ipv6_hdr *i6_hdr = (struct ipv6_hdr *)i_hdr;
		t_hdr->cksum = 0;
		t_hdr->cksum = rte_ipv6_udptcp_cksum(i6_hdr, t_hdr);
	}
}

/*
 * ftp_alg adjusting ACK from other end ;
 * ACK field of return packet to be adjusted
 * to the same value of length modified in the payload
 * Input - pkt, ack diff - delta
 * Output - None(void)
 */
static void  ftp_alg_adjust_tcp_ack(struct rte_mbuf *pkt, int16_t ackSeqdiff)
{
	/*Since v6 is not supported now*/
	uint16_t ip_hdr_size_bytes = IPv4_HEADER_SIZE;
	struct ipv4_hdr *iphdr = (struct ipv4_hdr *)
		RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);
	struct tcp_hdr *thdr = (struct tcp_hdr *)
		RTE_MBUF_METADATA_UINT32_PTR(pkt,
			IP_START + ip_hdr_size_bytes);
	/*
	* recv_ack and total length first to be chnaged to host byte order
	* and then do the addition and then set back to network byte order
	*/
	uint32_t temp;
	temp = rte_bswap32(thdr->recv_ack);
	//printf("%s: ackSeqdiff :%d %u\n", __FUNCTION__, ackSeqdiff, temp);
	if (ackSeqdiff < 0)
		temp += abs(ackSeqdiff);
	else
		temp -= abs(ackSeqdiff);

	thdr->recv_ack = rte_bswap32(temp);
}
/*
 * ftp_alg adjusting SEQ from other end ; SEQ field of onward/egress  packet
 * to be adjusted to the same value of length modified in the payload
 * Input - pkt, ack diff - delta
 * Output - None(void)
 */

static void  ftp_alg_adjust_tcp_seq(struct rte_mbuf *pkt, int16_t ackSeqdiff)
{
	/*Since v6 is not supported now*/
	uint16_t ip_hdr_size_bytes = IPv4_HEADER_SIZE;
	struct ipv4_hdr *iphdr = (struct ipv4_hdr *)
		RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);
	struct tcp_hdr *thdr = (struct tcp_hdr *)
		RTE_MBUF_METADATA_UINT32_PTR(pkt,
			IP_START + ip_hdr_size_bytes);
	uint32_t temp;

	temp = rte_bswap32(thdr->sent_seq);
	if (ackSeqdiff < 0)
		temp -= abs(ackSeqdiff);
	else
		temp += abs(ackSeqdiff);

	thdr->sent_seq = rte_bswap32(temp);
}
/*
 * ftp_alg adjusting SEQ from other end ; SEQ field of onward/egress  packet
 * to be adjusted to the same value of length modified in the payload;
 * This function computes the delta and calls adjust_seq for chaging the packet
 * Input - pkt,Original incoming String, Translated string and corresponding
 * lengths of the string
 * Output - Seq Diff between Original and translated string
 */

static int ftp_alg_delta_tcp_sequence(
	struct rte_mbuf *pkt,
	char *port_string,
	int16_t existing_tcpSeqdiff,
	uint16_t old_port_string_length,
	uint16_t new_port_string_length)
{
	int16_t current_sequence_number_delta=0;
	int16_t final_sequence_number_delta;
	/*Since v6 is not supported now*/
	uint16_t ip_hdr_size_bytes = IPv4_HEADER_SIZE;
	struct ipv4_hdr *iphdr = (struct ipv4_hdr *)
				RTE_MBUF_METADATA_UINT32_PTR(pkt, IP_START);
	struct tcp_hdr *thdr = (struct tcp_hdr *)
				RTE_MBUF_METADATA_UINT32_PTR(pkt,
					IP_START + ip_hdr_size_bytes);
	/*
	* recv_ack and total length first to be chnaged to host byte order
	* and then do the addition and then set back to network byte order
	*/
	current_sequence_number_delta = (int16_t) (new_port_string_length -
					old_port_string_length);
	iphdr->total_length = rte_bswap16(iphdr->total_length);

	#ifdef ALGDBG
	printf("total_length :%u\n", iphdr->total_length);
	#endif
	if(current_sequence_number_delta < 0)
		iphdr->total_length -= abs(current_sequence_number_delta);
	else
		iphdr->total_length += current_sequence_number_delta;

	iphdr->total_length = rte_bswap16(iphdr->total_length);
	if (existing_tcpSeqdiff !=0)
		ftp_alg_adjust_tcp_seq(pkt,existing_tcpSeqdiff);
	final_sequence_number_delta= current_sequence_number_delta + existing_tcpSeqdiff;
	return final_sequence_number_delta;
}


/*
 * ftp_alg dpi - this function parses the packet and does the respective
 * action based on the type PORT or PASV, based on the direction of packet
 * (Private or Public) This is called from CGNAPT
 * Input - cgnapt pipeline struct, cgnapt key, pkt, CT ,
 * position of packet assigned by CT, direction of packet
 * Output - None - as it calls respective action functions
 */
void ftp_alg_dpi(
	struct pipeline_cgnapt *p_nat,
	struct pipeline_cgnapt_entry_key *nat_entry_key,
	struct rte_mbuf *pkt,
	struct rte_ct_cnxn_tracker *cgnat_cnxn_tracker,
	int32_t ct_position,
	uint8_t direction)
{
	/*
	* recv_ack and total length first to be chnaged to host byte order
	* and then do the addition and then set back to network byte order
	*/

	/*entry key to be framed in cgnat and pass it over here*/
	char *port_cmd_string;
	char *port_cmd_end_string;
	char *tcp_header_end;
	char *tcp_start;


	uint16_t private_port_number;
	uint16_t public_port_number;
	uint16_t ip1, ip2, ip3, ip4, port1, port2;
	int16_t tcpSeqdiff = 0;
	int16_t ackSeqdiff, ackAdjust;
	uint32_t private_address;
	uint32_t public_address;
	uint8_t *bptr_private_address;
	/* also for PASV string */
	char port_string[65];
	char port_string_translated[FTP_MAXIMUM_PORT_STRING_LENGTH];
	int16_t new_port_string_length = 0;
	int16_t old_port_string_length;
	int dummy_value;
	struct cgnapt_table_entry *egress_entry = NULL, *ingress_entry;
	uint32_t ct_key[10];
	uint8_t key_direction;
	/*Since v6 is not supported now*/
	uint16_t ip_hdr_size_bytes = IPv4_HEADER_SIZE;

	struct ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(pkt,
			struct ipv4_hdr *, sizeof(struct ether_hdr));
	/* TCP and UDP ports at same offset,
	* just use TCP for offset calculation
	*/
	struct tcp_hdr *thdr = rte_pktmbuf_mtod_offset(pkt, struct tcp_hdr *,
			(sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr)));
	uint16_t src_port = rte_bswap16(thdr->src_port);
	uint16_t dst_port = rte_bswap16(thdr->dst_port);
	uint8_t proto = ip_hdr->next_proto_id;
	uint32_t src_addr = rte_bswap32(ip_hdr->src_addr);
	uint32_t dst_addr = rte_bswap32(ip_hdr->dst_addr);
	uint32_t tmp_tcp_paylod_size;

	#if 0
	- src_port & dst_port checking to be moved from cgnat to dpi
	- For control channel
		first validation of tcpSeqdiff to be checked
		IF <  > 0
			ftp_alg_tcp_ack() to be called(this includes PORT
			response and PASV response ack as well)
			Return
		ELSE
			the port/pasv paramter checkign to be done
	- For data channel
	-retreive ALG entry
		IF found
			- remove the ALG entry
		even if not found(found cases too)
	- set the bypass flag in the CT session table

	#endif

	#ifdef ALGDBG
	{
		printf("ftp port number: %d, %d\n", src_port, dst_port);
		printf("ftp TCP seq num diff: %d\n",
			cgnat_cnxn_tracker->hash_table_entries[
					ct_position].tcpSeqdiff);
		printf("tcp data offset: %d\n",
			((thdr->data_off & 0xf0) >> 2));
		printf("ct position in dpi:%d\n", ct_position);
	}
	#endif

	if (src_port == 21 || dst_port == 21)/* Control Channel*/{
	/* Control Channel Start */
	/*
	* need to look for the port or pasv command.  Then have to look for
	* the IP address and the port address. Then must create a TCP control
	* block and spoof the port number, and change the ip address, and do
	* the sequence number setting.
	*/
	/* Handle TCP headers.*/
	tcp_start = (char *)thdr;

	/* start of TCP payload */
	port_cmd_string = (char * )(tcp_start+((thdr->data_off & 0xf0) >> 2));
	tcp_header_end = port_cmd_string;

	if (direction == PRIVATE) {

		#ifdef ALGDBG
		printf("In PRIVATE  ");
		#endif

		cgnat_cnxn_tracker->hash_table_entries[ct_position].seq_client
				= rte_bswap32(thdr->sent_seq);
		cgnat_cnxn_tracker->hash_table_entries[ct_position].ack_client
				= rte_bswap32(thdr->recv_ack);
		#ifdef ALGDBG
		printf("-->Seq_cli:%u, Ack_cli:%u, Len:%4d\n",
			rte_bswap32(thdr->sent_seq),
			rte_bswap32(thdr->recv_ack),
			(rte_bswap16(ip_hdr->total_length) -
			(((thdr->data_off & 0xf0) >> 4) * 4)) - 20);
		#endif
	} else {

		#ifdef ALGDBG
		printf("In PUBLIC  ");
		#endif
		cgnat_cnxn_tracker->hash_table_entries[ct_position].seq_server
				= rte_bswap32(thdr->sent_seq);
		cgnat_cnxn_tracker->hash_table_entries[ct_position].ack_server
				= rte_bswap32(thdr->recv_ack);
		#ifdef ALGDBG
		printf("<--Seq_cli:%4d, Ack_cli%4d, Len:%4d\n",
		rte_bswap32(thdr->sent_seq), rte_bswap32(thdr->recv_ack),
		(ip_hdr->total_length - (((thdr->data_off & 0xf0) >> 2))
			- 20));
		#endif
	}

	if (sscanf(port_cmd_string, FTP_PASV_PARAMETER_STRING, &dummy_value,
		&ip1, &ip2, &ip3, &ip4, &port1, &port2) ==
		FTP_PASV_PARAMETER_COUNT){

	snprintf (port_string, sizeof(port_string), FTP_PASV_PARAMETER_STRING, FTP_PASV_RETURN_CODE,
		ip1, ip2, ip3, ip4, port1, port2);

	int i = 0;
	while (port_cmd_string[i] != '\r' && port_cmd_string[i+1] != '\n')
		i++;

	i += 2; // now it points to end of port cmd string.

	old_port_string_length = i;

	private_port_number = (uint16_t) (port1 * 0x100 + port2);
	bptr_private_address = (uint8_t *) &private_address;

	bptr_private_address[3] = (uint8_t) (ip4 & 0x00FF);
	bptr_private_address[2] = (uint8_t) (ip3 & 0x00FF);
	bptr_private_address[1] = (uint8_t) (ip2 & 0x00FF);
	bptr_private_address[0] = (uint8_t) (ip1 & 0x00FF);

	/* Not needed as got the position from CT*/

	if (direction == PUBLIC) {
	/*Client in Private, Server in Public*/
	/* Not to convert in the payload for PASV resp from Pub side*/
	/* Only Table creation and no payload modification*/
	/* DAta Channel also no need to create as it will be done by NAT
	* when initiated by Client later
	*/
	populate_ftp_alg_entry(private_address, private_port_number);
	/*
	* Bypass ALG flag to be set ,
	* seqnumber -delta either to be 0 or not needed ,
	* direction checking for all scenarios
	*/
	cgnat_cnxn_tracker->hash_table_entries[ct_position].
			server_direction = SERVER_IN_PUBLIC;
	cgnat_cnxn_tracker->hash_table_entries[ct_position].
			ftp_session_type= 1; // Passive session type
	} else if (direction == PRIVATE) {
	/*Client in Public , Server in Private*/

	struct pipeline_cgnapt_entry_key data_channel_key;
	private_address = rte_bswap32(private_address);
	data_channel_key.ip = private_address;
	data_channel_key.port = private_port_number;
	/* to be checked if it can be passed as param from NAT*/
	data_channel_key.pid = pkt->port;

	/* add_dynamic_cgnat_entry() */ /* for DAta Channel*/
	/*Will be getting Private IP and port from Server ,
	* with that NAPT entry egress and ingress can be added ,
	* for further data channel communication
	*/
        #ifdef FTP_ALG
	if (add_dynamic_cgnapt_entry_alg((struct pipeline *)p_nat,
	&data_channel_key, &egress_entry, &ingress_entry) == 0){

		#ifdef ALGDBG
		printf("Wrong FTP ALG packet\n");
		#endif
		//p_nat->invalid_packets |= pkt_mask;

		p_nat->naptDroppedPktCount++;

		#ifdef CGNAPT_DEBUGGING
		p_nat->naptDroppedPktCount4++;
		#endif
		return;
	}
	#endif

	tmp_tcp_paylod_size = rte_bswap16(ip_hdr->total_length) -
			((thdr->data_off & 0xf0) >> 2) - ip_hdr_size_bytes;
	cgnat_cnxn_tracker->hash_table_entries[ct_position].
			tcp_payload_size = tmp_tcp_paylod_size;
	if(egress_entry) {

		/*Adding ALG entry , params to be derived from egress entry*/
		populate_ftp_alg_entry(egress_entry->data.pub_ip,
				egress_entry->data.pub_port);

		/* payload modification */
		new_port_string_length = ftp_alg_modify_payload(egress_entry,
				port_string,
				port_string_translated, 1);
		strncpy(tcp_header_end, port_string_translated,
				strlen(port_string_translated));
		tcpSeqdiff = ftp_alg_delta_tcp_sequence( pkt, port_string,
			cgnat_cnxn_tracker->hash_table_entries
			[ct_position].tcpSeqdiff,
			old_port_string_length,
			new_port_string_length);

	}
	/* same as rte_synproxy_adjust_pkt_length() in ct */
	ftp_alg_modify_pkt_len(pkt);
	/*
	* Store sequence_number_delta in Session_data structure, also bypass
	* flag to be set as NO (expecting TCP ack from other end then set the
	* bypass accordingly , handled earlier in the function
	*/

	cgnat_cnxn_tracker->hash_table_entries[ct_position].
			alg_bypass_flag = NO_BYPASS;
	cgnat_cnxn_tracker->hash_table_entries[ct_position].
			tcpSeqdiff = tcpSeqdiff;
	cgnat_cnxn_tracker->hash_table_entries[ct_position].
			server_direction = SERVER_IN_PRIVATE;
	cgnat_cnxn_tracker->hash_table_entries[ct_position].
			ftp_session_type = 1; // Passive session type
		return;

	} /* PRIVATE dir */
	} else if (sscanf(port_cmd_string, FTP_PORT_PARAMETER_STRING,
			&ip1, &ip2, &ip3, &ip4, &port1, &port2) ==
				FTP_PORT_PARAMETER_COUNT){

		int i = 0;
		static uint8_t port_hit;
		while (port_cmd_string[i] != '\r' &&
			port_cmd_string[i+1] != '\n')
			i++;

		i += 2; // now it points to end of port cmd string.

		old_port_string_length = i;

		#ifdef ALGDBG
		printf( " Existing Seq Diff = %d", cgnat_cnxn_tracker->
			hash_table_entries[ct_position].tcpSeqdiff);
		printf("FTP ALG: FTP PORT command length: %d\n",
			old_port_string_length);
		#endif

		private_port_number = (uint16_t) (port1 * 0x100 + port2);

		#ifdef ALGDBG
		printf("FTP ALG: private port number before swap: %u\n",
				private_port_number);
		#endif

		bptr_private_address = (uint8_t *) &private_address;
		bptr_private_address[3] = (uint8_t) (ip4 & 0x00FF);
		bptr_private_address[2] = (uint8_t) (ip3 & 0x00FF);
		bptr_private_address[1] = (uint8_t) (ip2 & 0x00FF);
		bptr_private_address[0] = (uint8_t) (ip1 & 0x00FF);

		sprintf(port_string, FTP_PORT_PARAMETER_STRING, ip1, ip2,
				ip3, ip4, port1, port2);

		#ifdef ALGDBG
		printf("FTP ALG: FTP original PORT string: %d,%s\n",
				(int) strlen(port_string)-2, port_string);
		printf("prv addr: %x\n", private_address);
		#endif


		if (direction == PUBLIC) {
			/* Client in Public*/
			/* retreive_cgnat_entry()* for Data Channel*/
			/* Pub port and ip address to be used for framing key ,
			* the private phrase is a misnomer
			*/
			struct pipeline_cgnapt_entry_key data_channel_key;
			data_channel_key.ip = private_address;
			data_channel_key.port = private_port_number;
			data_channel_key.pid = 0xffff;


			cgnat_cnxn_tracker->hash_table_entries[ct_position].
				server_direction = SERVER_IN_PRIVATE;
			cgnat_cnxn_tracker->hash_table_entries[ct_position].
				ftp_session_type= 0; // Active session type

			/* No payload modificaiton*/
			#ifdef ALGDBG
			printf("<--Seq_cli:%4d, Ack_cli%4d, Len:%4d\n",
			rte_bswap32(thdr->sent_seq),
			rte_bswap32(thdr->recv_ack),
			(ip_hdr->total_length -
				(((thdr->data_off & 0xf0) >> 2)) - 20));
			#endif
			populate_ftp_alg_entry(private_address, private_port_number);
		} else if (direction == PRIVATE) {

			/* Client in Private Server in Public*/
			/* Populate_alg_entry*/
			/*add_dynamic_cgnapt_entry()*/
			/* payload modificaion*/
			struct pipeline_cgnapt_entry_key data_channel_key;
			private_address = rte_bswap32(private_address);
			data_channel_key.ip = private_address;
			data_channel_key.port = private_port_number;
			/* to be checked if it can be passed as param from NAT*/
			data_channel_key.pid = pkt->port;

			/* add_dynamic_cgnat_entry() */ /* for DAta Channel*/
			/*
			* Will be getting Private IP and port from Client ,
			* with that NAPT entry egress and ingress can be added ,
			* for further data channel communication
			*/

                        #ifdef FTP_ALG
			if (add_dynamic_cgnapt_entry_alg((struct pipeline *)
				p_nat, &data_channel_key, &egress_entry,
				&ingress_entry) == 0){

				#ifdef ALGDBG
				printf("Wrong FTP ALG packet\n");
				#endif
				//p_nat->invalid_packets |= pkt_mask;
				p_nat->naptDroppedPktCount++;

				#ifdef CGNAPT_DEBUGGING
				p_nat->naptDroppedPktCount4++;
				#endif
				return;
			}
                        #endif

		tmp_tcp_paylod_size = rte_bswap16(ip_hdr->total_length) -
					((thdr->data_off & 0xf0) >> 2) -
					ip_hdr_size_bytes;
		cgnat_cnxn_tracker->hash_table_entries[ct_position].
			tcp_payload_size = tmp_tcp_paylod_size;
		/*ALG entry add, params to be derived from egress entry*/

		if(egress_entry) {
			populate_ftp_alg_entry(egress_entry->data.pub_ip,
					egress_entry->data.pub_port);
			/* payload modification */
			new_port_string_length = ftp_alg_modify_payload(egress_entry,
					port_string,
					port_string_translated, 0);
			strncpy(tcp_header_end, port_string_translated,
					strlen(port_string_translated));
			tcpSeqdiff = ftp_alg_delta_tcp_sequence( pkt, port_string,
					cgnat_cnxn_tracker->hash_table_entries
					[ct_position].tcpSeqdiff,
					old_port_string_length,
					new_port_string_length);
		}
		/* same as rte_synproxy_adjust_pkt_length() in ct */
		ftp_alg_modify_pkt_len(pkt);

		/*
		* Store sequence_number_delta in Session_data structure ,
		* also bypass flag to be set as NO
		* While response from other end is received ,
		* modify the ack no using reverse sign of sequen
		*/

		cgnat_cnxn_tracker->hash_table_entries[ct_position].
			alg_bypass_flag = NO_BYPASS;
		cgnat_cnxn_tracker->hash_table_entries[ct_position].
			tcpSeqdiff = tcpSeqdiff;
		cgnat_cnxn_tracker->hash_table_entries[ct_position].
			server_direction = SERVER_IN_PUBLIC;
		cgnat_cnxn_tracker->hash_table_entries[ct_position].
			ftp_session_type = 0; // Active session type

		#ifdef ALGDBG
		printf("<--Seq_cli:%4d, Ack_cli%4d, Len:%4d\n",
			rte_bswap32(thdr->sent_seq),
			rte_bswap32(thdr->recv_ack),
			(ip_hdr->total_length -
			(((thdr->data_off & 0xf0) >> 2)) - 20));

		#endif
		return;
		} /* PRIVATE dir */
	} /* PORT cmd message */

	if ((ackAdjust=cgnat_cnxn_tracker->hash_table_entries[
			ct_position].tcpSeqdiff) != 0) {
		if (direction == PRIVATE) {
			if (
				cgnat_cnxn_tracker->hash_table_entries
				[ct_position].seq_client !=
				cgnat_cnxn_tracker->hash_table_entries
				[ct_position].ack_server) {
				static int Seqhits;
				ftp_alg_adjust_tcp_seq( pkt,ackAdjust);
				tmp_tcp_paylod_size = rte_bswap16(
					ip_hdr->total_length) -
					((thdr->data_off & 0xf0) >> 2) -
					ip_hdr_size_bytes;
				cgnat_cnxn_tracker->hash_table_entries
				[ct_position].tcp_payload_size = tmp_tcp_paylod_size;
		#ifdef ALGDBG
                printf("<--Seq_cli:%4d, Ack_cli%4d, Len:%4d\n",
			rte_bswap32(thdr->sent_seq),
			rte_bswap32(thdr->recv_ack),
			(ip_hdr->total_length -(((thdr->data_off & 0xf0) >> 2))- 20));
		#endif
			}
		} else {
			if (cgnat_cnxn_tracker->hash_table_entries
				[ct_position].ack_server !=
				(cgnat_cnxn_tracker->hash_table_entries
				[ct_position].seq_client +
				cgnat_cnxn_tracker->hash_table_entries
				[ct_position].tcp_payload_size)) {
				static int Ackhits;
				ftp_alg_adjust_tcp_ack( pkt,ackAdjust);
		#ifdef ALGDBG
                printf("<--Seq_cli:%4d, Ack_cli%4d, Len:%4d\n",
			rte_bswap32(thdr->sent_seq),
			rte_bswap32(thdr->recv_ack),
			(ip_hdr->total_length -(((thdr->data_off & 0xf0) >> 2))- 20));
		#endif
			}
		}
		return;
			} /* expected_ack and sequence number updation for PUBLIC dir TCP window */
	} /* Control Channel End */
	else {
		/*remove the ALG entry, retreival is taken care by rte function  */
		#ifdef ALGDBG
		printf("In Data Channel \n");
		#endif
		remove_ftp_alg_entry (dst_addr,dst_port);/* remove the ALG entry */
		cgnat_cnxn_tracker->hash_table_entries[ct_position].alg_bypass_flag = BYPASS;
	} /* Data Channel End */
}
