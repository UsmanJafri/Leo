
#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;

// 14 byte
header ethernet_h {
	mac_addr_t dst_addr;
	mac_addr_t src_addr;
	ether_type_t ether_type;
}

// 20 byte
header ipv4_h {
	bit<4> version;
	bit<4> ihl;
	bit<8> diffserv;
	bit<16> total_len;
	bit<16> identification;
	bit<3> flags;
	bit<13> frag_offset;
	bit<8> ttl;
	ip_protocol_t protocol;
	bit<16> hdr_checksum;
	ipv4_addr_t src_addr;
	ipv4_addr_t dst_addr;
}

// 20 byte
header tcp_h {
	bit<16> src_port;
	bit<16> dst_port;
	bit<32> seq_no;
	bit<32> ack_no;
	bit<4> data_offset;
	bit<4> res;
	bit<1>  cwr;
	bit<1>  ece;
	bit<1>  urg;
	bit<1>  ack;
	bit<1>  psh;
	bit<1>  rst;
	bit<1>  syn;
	bit<1>  fin;
	bit<16> window;
	bit<16> checksum;
	bit<16> urgent_ptr;
}

#define FEATURE_WIDTH 16
#define LEAF_ID_WIDTH 16
#define ALU_RESULT_WIDTH 8

header classification_t {
	bit<LEAF_ID_WIDTH> leaf;
	bit<LEAF_ID_WIDTH> layer_1_result;
	bit<LEAF_ID_WIDTH> layer_2_result;
	bit<LEAF_ID_WIDTH> layer_3_result;
	bit<LEAF_ID_WIDTH> layer_4_result;
	bit<FEATURE_WIDTH> alu_1_input;
	bit<FEATURE_WIDTH> alu_1_result;
	bit<FEATURE_WIDTH> alu_2_input;
	bit<FEATURE_WIDTH> alu_2_result;
	bit<FEATURE_WIDTH> alu_3_input;
	bit<FEATURE_WIDTH> alu_3_result;
	bit<FEATURE_WIDTH> alu_4_input;
	bit<FEATURE_WIDTH> alu_4_result;
	bit<FEATURE_WIDTH> alu_5_input;
	bit<FEATURE_WIDTH> alu_5_result;
	bit<FEATURE_WIDTH> alu_6_input;
	bit<FEATURE_WIDTH> alu_6_result;
	bit<FEATURE_WIDTH> alu_7_input;
	bit<FEATURE_WIDTH> alu_7_result;
	bit<FEATURE_WIDTH> feature_1;
	bit<FEATURE_WIDTH> feature_2;

	bit<48> start_time;
	bit<48> end_time;
	bit<48> backup_time;
	bit<8> ctrl;
	bit<8> dummy;
}


header resubmit_header_t {
	bit<8>  type;
	bit<8> class_id;
	}

struct header_t {
	ethernet_h ethernet;
	ipv4_h ipv4;
	tcp_h tcp;
	classification_t class;
}

#include "tofino-util.p4"

const bit<8> RESUB_TYPE = 255;

struct metadata_t {
	bit<8>          resub_type;
	resubmit_header_t resub_hdr;
}

typedef bit<9>  egressSpec_t;

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
		packet_in pkt,
		out header_t hdr,
		out metadata_t ig_md,
		out ingress_intrinsic_metadata_t ig_intr_md) {

	state start {
	   pkt.extract(ig_intr_md);
	   ig_md.resub_type = 0;
		transition select(ig_intr_md.resubmit_flag) {
			1 : parse_resubmit;
			0 : parse_port_metadata;
		}
	}

	state parse_resubmit {
		ig_md.resub_type = pkt.lookahead<bit<8>>()[7:0];
		transition select(ig_md.resub_type) {
			RESUB_TYPE : parse_resub;
			default : reject;
		}
	}

	state parse_resub {
		pkt.extract(ig_md.resub_hdr);
		transition parse_resub_end;
	}

	state parse_resub_end {
		transition parse_ethernet;
	}

	state parse_port_metadata {
		pkt.advance(PORT_METADATA_SIZE);
		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type) {
			ETHERTYPE_IPV4: parse_ipv4;
			default: reject;
		}
	}

	state parse_ipv4 {
		pkt.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol){
			IP_PROTOCOLS_TCP: parse_tcp;
			default: reject;
		}
	}

	state parse_tcp {
	   pkt.extract(hdr.tcp);
	   transition parse_class_hdr;
	}

	state parse_class_hdr {
	   pkt.extract(hdr.class);
	   transition accept;
	}
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------

control SwitchIngressDeparser(
		packet_out pkt,
		inout header_t hdr,
		in metadata_t ig_md,
		in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

	Checksum() ipv4_checksum;

	apply {
		hdr.ipv4.hdr_checksum = ipv4_checksum.update({
			hdr.ipv4.version,
			hdr.ipv4.ihl,
			hdr.ipv4.diffserv,
			hdr.ipv4.total_len,
			hdr.ipv4.identification,
			hdr.ipv4.flags,
			hdr.ipv4.frag_offset,
			hdr.ipv4.ttl,
			hdr.ipv4.protocol,
			hdr.ipv4.src_addr,
			hdr.ipv4.dst_addr});

		pkt.emit(hdr.ethernet);
		pkt.emit(hdr.ipv4);
		pkt.emit(hdr.tcp);
		pkt.emit(hdr.class);
	}
}

// ---------------------------------------------------------------------------
// Ingress 
// ---------------------------------------------------------------------------
control SwitchIngress(
		inout header_t hdr,
		inout metadata_t ig_md,
		in ingress_intrinsic_metadata_t ig_intr_md,
		in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
		inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
		inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

	const PortId_t CPU_PORT = 64;

	action drop() {
		ig_dprsr_md.drop_ctl = 1;
	}

	action ipv4_forward(egressSpec_t port) {
		ig_tm_md.ucast_egress_port = port;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}

	action send_to_cpu() {
		ig_tm_md.ucast_egress_port = CPU_PORT;
	}

	table ipv4_exact {
		key = {
			hdr.ipv4.dst_addr: exact;
		}
		actions = {
			ipv4_forward;
			send_to_cpu;
			drop;
		}
		size = 10000;
		default_action = send_to_cpu();
	}

	action set_leaf(bit<LEAF_ID_WIDTH> leaf) {
		hdr.class.leaf = leaf;
	}

	action ALU_1_and() {
		hdr.class.alu_1_result = hdr.class.alu_1_input & 32768;
	}

	action ALU_2_and() {
		hdr.class.alu_2_result = hdr.class.alu_2_input & 32768;
	}

	action ALU_3_and() {
		hdr.class.alu_3_result = hdr.class.alu_3_input & 32768;
	}

	action ALU_4_and() {
		hdr.class.alu_4_result = hdr.class.alu_4_input & 32768;
	}

	action ALU_5_and() {
		hdr.class.alu_5_result = hdr.class.alu_5_input & 32768;
	}

	action ALU_6_and() {
		hdr.class.alu_6_result = hdr.class.alu_6_input & 32768;
	}

	action ALU_7_and() {
		hdr.class.alu_7_result = hdr.class.alu_7_input & 32768;
	}

	action set_1_1_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_1_input = hdr.class.feature_1 + constraint;
	}

	action set_1_1_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_1_input = hdr.class.feature_2 + constraint;
	}

	table layer_1_1 {
		key = {
			hdr.class.dummy : exact;
		}
		actions = {
			set_1_1_feature1;
			set_1_1_feature2;
			NoAction;
		}
		size = 2;
		default_action = NoAction();
	}

	action set_1_2_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_2_input = hdr.class.feature_1 + constraint;
	}

	action set_1_2_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_2_input = hdr.class.feature_2 + constraint;
	}

	table layer_1_2 {
		key = {
			hdr.class.dummy : exact;
		}
		actions = {
			set_1_2_feature1;
			set_1_2_feature2;
			NoAction;
		}
		size = 2;
		default_action = NoAction();
	}

	action set_1_3_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_3_input = hdr.class.feature_1 + constraint;
	}

	action set_1_3_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_3_input = hdr.class.feature_2 + constraint;
	}

	table layer_1_3 {
		key = {
			hdr.class.dummy : exact;
		}
		actions = {
			set_1_3_feature1;
			set_1_3_feature2;
			NoAction;
		}
		size = 2;
		default_action = NoAction();
	}

	action set_1_4_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_4_input = hdr.class.feature_1 + constraint;
	}

	action set_1_4_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_4_input = hdr.class.feature_2 + constraint;
	}

	table layer_1_4 {
		key = {
			hdr.class.dummy : exact;
		}
		actions = {
			set_1_4_feature1;
			set_1_4_feature2;
			NoAction;
		}
		size = 2;
		default_action = NoAction();
	}

	action set_1_5_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_5_input = hdr.class.feature_1 + constraint;
	}

	action set_1_5_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_5_input = hdr.class.feature_2 + constraint;
	}

	table layer_1_5 {
		key = {
			hdr.class.dummy : exact;
		}
		actions = {
			set_1_5_feature1;
			set_1_5_feature2;
			NoAction;
		}
		size = 2;
		default_action = NoAction();
	}

	action set_1_6_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_6_input = hdr.class.feature_1 + constraint;
	}

	action set_1_6_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_6_input = hdr.class.feature_2 + constraint;
	}

	table layer_1_6 {
		key = {
			hdr.class.dummy : exact;
		}
		actions = {
			set_1_6_feature1;
			set_1_6_feature2;
			NoAction;
		}
		size = 2;
		default_action = NoAction();
	}

	action set_1_7_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_7_input = hdr.class.feature_1 + constraint;
	}

	action set_1_7_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_7_input = hdr.class.feature_2 + constraint;
	}

	table layer_1_7 {
		key = {
			hdr.class.dummy : exact;
		}
		actions = {
			set_1_7_feature1;
			set_1_7_feature2;
			NoAction;
		}
		size = 2;
		default_action = NoAction();
	}

	action set_2_1_feature1(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.class.layer_1_result = result;
		hdr.class.alu_1_input = hdr.class.feature_1 + constraint;
	}

	action set_2_1_feature2(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.class.layer_1_result = result;
		hdr.class.alu_1_input = hdr.class.feature_2 + constraint;
	}

	table layer_2_1 {
		key = {
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
		set_leaf;
			set_2_1_feature1;
			set_2_1_feature2;
			NoAction;
		}
		size = 256;
		default_action = NoAction();
	}

	action set_2_2_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_2_input = hdr.class.feature_1 + constraint;
	}

	action set_2_2_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_2_input = hdr.class.feature_2 + constraint;
	}

	table layer_2_2 {
		key = {
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_2_2_feature1;
			set_2_2_feature2;
			NoAction;
		}
		size = 256;
		default_action = NoAction();
	}

	action set_2_3_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_3_input = hdr.class.feature_1 + constraint;
	}

	action set_2_3_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_3_input = hdr.class.feature_2 + constraint;
	}

	table layer_2_3 {
		key = {
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_2_3_feature1;
			set_2_3_feature2;
			NoAction;
		}
		size = 256;
		default_action = NoAction();
	}

	action set_2_4_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_4_input = hdr.class.feature_1 + constraint;
	}

	action set_2_4_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_4_input = hdr.class.feature_2 + constraint;
	}

	table layer_2_4 {
		key = {
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_2_4_feature1;
			set_2_4_feature2;
			NoAction;
		}
		size = 256;
		default_action = NoAction();
	}

	action set_2_5_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_5_input = hdr.class.feature_1 + constraint;
	}

	action set_2_5_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_5_input = hdr.class.feature_2 + constraint;
	}

	table layer_2_5 {
		key = {
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_2_5_feature1;
			set_2_5_feature2;
			NoAction;
		}
		size = 256;
		default_action = NoAction();
	}

	action set_2_6_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_6_input = hdr.class.feature_1 + constraint;
	}

	action set_2_6_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_6_input = hdr.class.feature_2 + constraint;
	}

	table layer_2_6 {
		key = {
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_2_6_feature1;
			set_2_6_feature2;
			NoAction;
		}
		size = 256;
		default_action = NoAction();
	}

	action set_2_7_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_7_input = hdr.class.feature_1 + constraint;
	}

	action set_2_7_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_7_input = hdr.class.feature_2 + constraint;
	}

	table layer_2_7 {
		key = {
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_2_7_feature1;
			set_2_7_feature2;
			NoAction;
		}
		size = 256;
		default_action = NoAction();
	}

	action set_3_1_feature1(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.class.layer_2_result = result;
		hdr.class.alu_1_input = hdr.class.feature_1 + constraint;
	}

	action set_3_1_feature2(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.class.layer_2_result = result;
		hdr.class.alu_1_input = hdr.class.feature_2 + constraint;
	}

	table layer_3_1 {
		key = {
			hdr.class.layer_1_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
		set_leaf;
			set_3_1_feature1;
			set_3_1_feature2;
			NoAction;
		}
		size = 2048;
		default_action = NoAction();
	}

	action set_3_2_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_2_input = hdr.class.feature_1 + constraint;
	}

	action set_3_2_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_2_input = hdr.class.feature_2 + constraint;
	}

	table layer_3_2 {
		key = {
			hdr.class.layer_1_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_3_2_feature1;
			set_3_2_feature2;
			NoAction;
		}
		size = 2048;
		default_action = NoAction();
	}

	action set_3_3_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_3_input = hdr.class.feature_1 + constraint;
	}

	action set_3_3_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_3_input = hdr.class.feature_2 + constraint;
	}

	table layer_3_3 {
		key = {
			hdr.class.layer_1_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_3_3_feature1;
			set_3_3_feature2;
			NoAction;
		}
		size = 2048;
		default_action = NoAction();
	}

	action set_3_4_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_4_input = hdr.class.feature_1 + constraint;
	}

	action set_3_4_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_4_input = hdr.class.feature_2 + constraint;
	}

	table layer_3_4 {
		key = {
			hdr.class.layer_1_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_3_4_feature1;
			set_3_4_feature2;
			NoAction;
		}
		size = 2048;
		default_action = NoAction();
	}

	action set_3_5_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_5_input = hdr.class.feature_1 + constraint;
	}

	action set_3_5_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_5_input = hdr.class.feature_2 + constraint;
	}

	table layer_3_5 {
		key = {
			hdr.class.layer_1_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_3_5_feature1;
			set_3_5_feature2;
			NoAction;
		}
		size = 2048;
		default_action = NoAction();
	}

	action set_3_6_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_6_input = hdr.class.feature_1 + constraint;
	}

	action set_3_6_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_6_input = hdr.class.feature_2 + constraint;
	}

	table layer_3_6 {
		key = {
			hdr.class.layer_1_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_3_6_feature1;
			set_3_6_feature2;
			NoAction;
		}
		size = 2048;
		default_action = NoAction();
	}

	action set_3_7_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_7_input = hdr.class.feature_1 + constraint;
	}

	action set_3_7_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_7_input = hdr.class.feature_2 + constraint;
	}

	table layer_3_7 {
		key = {
			hdr.class.layer_1_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_3_7_feature1;
			set_3_7_feature2;
			NoAction;
		}
		size = 2048;
		default_action = NoAction();
	}

	action set_4_1_feature1(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.class.layer_3_result = result;
		hdr.class.alu_1_input = hdr.class.feature_1 + constraint;
	}

	action set_4_1_feature2(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.class.layer_3_result = result;
		hdr.class.alu_1_input = hdr.class.feature_2 + constraint;
	}

	table layer_4_1 {
		key = {
			hdr.class.layer_2_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
		set_leaf;
			set_4_1_feature1;
			set_4_1_feature2;
			NoAction;
		}
		size = 16384;
		default_action = NoAction();
	}

	action set_4_2_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_2_input = hdr.class.feature_1 + constraint;
	}

	action set_4_2_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_2_input = hdr.class.feature_2 + constraint;
	}

	table layer_4_2 {
		key = {
			hdr.class.layer_2_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_4_2_feature1;
			set_4_2_feature2;
			NoAction;
		}
		size = 16384;
		default_action = NoAction();
	}

	action set_4_3_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_3_input = hdr.class.feature_1 + constraint;
	}

	action set_4_3_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_3_input = hdr.class.feature_2 + constraint;
	}

	table layer_4_3 {
		key = {
			hdr.class.layer_2_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_4_3_feature1;
			set_4_3_feature2;
			NoAction;
		}
		size = 16384;
		default_action = NoAction();
	}

	action set_4_4_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_4_input = hdr.class.feature_1 + constraint;
	}

	action set_4_4_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_4_input = hdr.class.feature_2 + constraint;
	}

	table layer_4_4 {
		key = {
			hdr.class.layer_2_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_4_4_feature1;
			set_4_4_feature2;
			NoAction;
		}
		size = 16384;
		default_action = NoAction();
	}

	action set_4_5_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_5_input = hdr.class.feature_1 + constraint;
	}

	action set_4_5_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_5_input = hdr.class.feature_2 + constraint;
	}

	table layer_4_5 {
		key = {
			hdr.class.layer_2_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_4_5_feature1;
			set_4_5_feature2;
			NoAction;
		}
		size = 16384;
		default_action = NoAction();
	}

	action set_4_6_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_6_input = hdr.class.feature_1 + constraint;
	}

	action set_4_6_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_6_input = hdr.class.feature_2 + constraint;
	}

	table layer_4_6 {
		key = {
			hdr.class.layer_2_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_4_6_feature1;
			set_4_6_feature2;
			NoAction;
		}
		size = 16384;
		default_action = NoAction();
	}

	action set_4_7_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_7_input = hdr.class.feature_1 + constraint;
	}

	action set_4_7_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_7_input = hdr.class.feature_2 + constraint;
	}

	table layer_4_7 {
		key = {
			hdr.class.layer_2_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_4_7_feature1;
			set_4_7_feature2;
			NoAction;
		}
		size = 16384;
		default_action = NoAction();
	}

	action set_5_1_feature1(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.class.layer_4_result = result;
		hdr.class.alu_1_input = hdr.class.feature_1 + constraint;
	}

	action set_5_1_feature2(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.class.layer_4_result = result;
		hdr.class.alu_1_input = hdr.class.feature_2 + constraint;
	}

	table layer_5_1 {
		key = {
			hdr.class.layer_3_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
		set_leaf;
			set_5_1_feature1;
			set_5_1_feature2;
			NoAction;
		}
		size = 131072;
		default_action = NoAction();
	}

	action set_5_2_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_2_input = hdr.class.feature_1 + constraint;
	}

	action set_5_2_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_2_input = hdr.class.feature_2 + constraint;
	}

	table layer_5_2 {
		key = {
			hdr.class.layer_3_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_5_2_feature1;
			set_5_2_feature2;
			NoAction;
		}
		size = 131072;
		default_action = NoAction();
	}

	action set_5_3_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_3_input = hdr.class.feature_1 + constraint;
	}

	action set_5_3_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_3_input = hdr.class.feature_2 + constraint;
	}

	table layer_5_3 {
		key = {
			hdr.class.layer_3_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_5_3_feature1;
			set_5_3_feature2;
			NoAction;
		}
		size = 131072;
		default_action = NoAction();
	}

	action set_5_4_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_4_input = hdr.class.feature_1 + constraint;
	}

	action set_5_4_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_4_input = hdr.class.feature_2 + constraint;
	}

	table layer_5_4 {
		key = {
			hdr.class.layer_3_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_5_4_feature1;
			set_5_4_feature2;
			NoAction;
		}
		size = 131072;
		default_action = NoAction();
	}

	action set_5_5_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_5_input = hdr.class.feature_1 + constraint;
	}

	action set_5_5_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_5_input = hdr.class.feature_2 + constraint;
	}

	table layer_5_5 {
		key = {
			hdr.class.layer_3_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_5_5_feature1;
			set_5_5_feature2;
			NoAction;
		}
		size = 131072;
		default_action = NoAction();
	}

	action set_5_6_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_6_input = hdr.class.feature_1 + constraint;
	}

	action set_5_6_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_6_input = hdr.class.feature_2 + constraint;
	}

	table layer_5_6 {
		key = {
			hdr.class.layer_3_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_5_6_feature1;
			set_5_6_feature2;
			NoAction;
		}
		size = 131072;
		default_action = NoAction();
	}

	action set_5_7_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_7_input = hdr.class.feature_1 + constraint;
	}

	action set_5_7_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.class.alu_7_input = hdr.class.feature_2 + constraint;
	}

	table layer_5_7 {
		key = {
			hdr.class.layer_3_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
			set_5_7_feature1;
			set_5_7_feature2;
			NoAction;
		}
		size = 131072;
		default_action = NoAction();
	}

	table layer_6_1 {
		key = {
			hdr.class.layer_4_result : exact;
			hdr.class.alu_1_result : exact;
			hdr.class.alu_2_result : exact;
			hdr.class.alu_3_result : exact;
			hdr.class.alu_4_result : exact;
			hdr.class.alu_5_result : exact;
			hdr.class.alu_6_result : exact;
			hdr.class.alu_7_result : exact;
		}
		actions = {
		set_leaf;
			NoAction;
		}
		size = 1048576;
		default_action = NoAction();
	}

	apply {
		hdr.class.start_time = ig_intr_md.ingress_mac_tstamp;

		layer_1_1.apply();
		layer_1_2.apply();
		layer_1_3.apply();
		layer_1_4.apply();
		layer_1_5.apply();
		layer_1_6.apply();
		layer_1_7.apply();
		ALU_1_and();
		ALU_2_and();
		ALU_3_and();
		ALU_4_and();
		ALU_5_and();
		ALU_6_and();
		ALU_7_and();
		layer_2_1.apply();
		layer_2_2.apply();
		layer_2_3.apply();
		layer_2_4.apply();
		layer_2_5.apply();
		layer_2_6.apply();
		layer_2_7.apply();
		ALU_1_and();
		ALU_2_and();
		ALU_3_and();
		ALU_4_and();
		ALU_5_and();
		ALU_6_and();
		ALU_7_and();
		layer_3_1.apply();
		layer_3_2.apply();
		layer_3_3.apply();
		layer_3_4.apply();
		layer_3_5.apply();
		layer_3_6.apply();
		layer_3_7.apply();
		ALU_1_and();
		ALU_2_and();
		ALU_3_and();
		ALU_4_and();
		ALU_5_and();
		ALU_6_and();
		ALU_7_and();
		layer_4_1.apply();
		layer_4_2.apply();
		layer_4_3.apply();
		layer_4_4.apply();
		layer_4_5.apply();
		layer_4_6.apply();
		layer_4_7.apply();
		ALU_1_and();
		ALU_2_and();
		ALU_3_and();
		ALU_4_and();
		ALU_5_and();
		ALU_6_and();
		ALU_7_and();
		layer_5_1.apply();
		layer_5_2.apply();
		layer_5_3.apply();
		layer_5_4.apply();
		layer_5_5.apply();
		layer_5_6.apply();
		layer_5_7.apply();
		ALU_1_and();
		ALU_2_and();
		ALU_3_and();
		ALU_4_and();
		ALU_5_and();
		ALU_6_and();
		ALU_7_and();
		layer_6_1.apply();


		if (hdr.ipv4.isValid()) {
			ipv4_exact.apply();
		}
	}
}

// ---------------------------------------------------------------------------
// Egress Parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(
		packet_in pkt,
		out header_t hdr,
		out metadata_t eg_md,
		out egress_intrinsic_metadata_t eg_intr_md) {

	TofinoEgressParser() tofino_parser;

	state start {
		tofino_parser.apply(pkt, eg_intr_md);
		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type) {
			ETHERTYPE_IPV4 : parse_ipv4;
			default : reject;
		}
	}

	state parse_ipv4 {
		pkt.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol){
			IP_PROTOCOLS_TCP: parse_tcp;
			default: reject;
		}
	}

	state parse_tcp {
	   pkt.extract(hdr.tcp);
	   transition parse_class_hdr;
	}

	state parse_class_hdr {
	   pkt.extract(hdr.class);
	   transition accept;
	}
}


// ---------------------------------------------------------------------------
// Egress 
// ---------------------------------------------------------------------------
control SwitchEgress(
		inout header_t hdr,
		inout metadata_t eg_md,
		in egress_intrinsic_metadata_t eg_intr_md,
		in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
		inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
		inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

	apply {
		hdr.class.end_time = eg_intr_from_prsr.global_tstamp;
		hdr.class.ctrl = 0xff;
	}
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(packet_out pkt,
							  inout header_t hdr,
							  in metadata_t eg_md,
							  in egress_intrinsic_metadata_for_deparser_t 
								eg_intr_dprsr_md
							  ) {

	apply {
		pkt.emit(hdr.ethernet);
		pkt.emit(hdr.ipv4);
		pkt.emit(hdr.tcp);
		pkt.emit(hdr.class);
	}
}

Pipeline(SwitchIngressParser(),
		 SwitchIngress(),
		 SwitchIngressDeparser(),
		 SwitchEgressParser(),
		 SwitchEgress(),
		 SwitchEgressDeparser()) pipe;

Switch(pipe) main;
