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
typedef bit<128> ipv6_addr_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;

// 14 byte
header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
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
    bit<8> protocol;
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
#define CODE_WIDTH 4
#define FEATURE_TABLE_SIZE 20470
#define LEAF_TABLE_SIZE 1099554

header classification_t {
    bit<8> leaf;
    bit<FEATURE_WIDTH> feature1;
    bit<FEATURE_WIDTH> feature2;
    bit<FEATURE_WIDTH> feature3;
    bit<FEATURE_WIDTH> feature4;
    bit<FEATURE_WIDTH> feature5;
    bit<FEATURE_WIDTH> feature6;
    bit<FEATURE_WIDTH> feature7;
    bit<FEATURE_WIDTH> feature8;
    bit<FEATURE_WIDTH> feature9;
    bit<FEATURE_WIDTH> feature10;
    bit<FEATURE_WIDTH> feature11;
    bit<FEATURE_WIDTH> feature12;
    bit<FEATURE_WIDTH> feature13;
    bit<FEATURE_WIDTH> feature14;
    bit<CODE_WIDTH> code1;
    bit<CODE_WIDTH> code2;
    bit<CODE_WIDTH> code3;
    bit<CODE_WIDTH> code4;
    bit<CODE_WIDTH> code5;
    bit<CODE_WIDTH> code6;
    bit<CODE_WIDTH> code7;
    bit<CODE_WIDTH> code8;
    bit<CODE_WIDTH> code9;
    bit<CODE_WIDTH> code10;
    bit<CODE_WIDTH> code11;
    bit<CODE_WIDTH> code12;
    bit<CODE_WIDTH> code13;
    bit<CODE_WIDTH> code14;
}

header resubmit_header_t {
    bit<8>  type;
    bit<8> class_id;
}
const bit<8> RESUB_TYPE = 255;
const bit<3> DPRSR_DIGEST_TYPE = 0;

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    classification_t class;
}

#include "tofino-util.p4"

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
            hdr.ipv4.dst_addr: ternary;
        }
        actions = {
            ipv4_forward;
            drop;
            send_to_cpu;
        }
        size = 10000;
        default_action = send_to_cpu();
    }

	action set_code1(bit<CODE_WIDTH> code) {
        hdr.class.code1 = code;
    }

    table f1 {
        key = {
            hdr.class.feature1: ternary;
        }
        actions = {
            set_code1;
            NoAction;
        }
        size = FEATURE_TABLE_SIZE;
        default_action = NoAction();
    }

	action set_code2(bit<CODE_WIDTH> code) {
        hdr.class.code2 = code;
    }

    table f2 {
        key = {
            hdr.class.feature2: ternary;
        }
        actions = {
            set_code2;
            NoAction;
        }
        size = FEATURE_TABLE_SIZE;
        default_action = NoAction();
    }

	action set_code3(bit<CODE_WIDTH> code) {
        hdr.class.code3 = code;
    }

    table f3 {
        key = {
            hdr.class.feature3: ternary;
        }
        actions = {
            set_code3;
            NoAction;
        }
        size = FEATURE_TABLE_SIZE;
        default_action = NoAction();
    }
	action set_code4(bit<CODE_WIDTH> code) {
        hdr.class.code4 = code;
    }

    table f4 {
        key = {
            hdr.class.feature4: ternary;
        }
        actions = {
            set_code4;
            NoAction;
        }
        size = FEATURE_TABLE_SIZE;
        default_action = NoAction();
    }

	action set_code5(bit<CODE_WIDTH> code) {
        hdr.class.code5 = code;
    }

    table f5 {
        key = {
            hdr.class.feature5: ternary;
        }
        actions = {
            set_code5;
            NoAction;
        }
        size = FEATURE_TABLE_SIZE;
        default_action = NoAction();
    }

  	action set_code6(bit<CODE_WIDTH> code) {
        hdr.class.code6 = code;
    }

    table f6 {
        key = {
            hdr.class.feature6: ternary;
        }
        actions = {
            set_code6;
            NoAction;
        }
        size = FEATURE_TABLE_SIZE;
        default_action = NoAction();
    }

	action set_code7(bit<CODE_WIDTH> code) {
        hdr.class.code7 = code;
    }

    table f7 {
        key = {
            hdr.class.feature7: ternary;
        }
        actions = {
            set_code7;
            NoAction;
        }
        size = FEATURE_TABLE_SIZE;
        default_action = NoAction();
    }

	action set_code8(bit<CODE_WIDTH> code) {
        hdr.class.code8 = code;
    }

    table f8 {
        key = {
            hdr.class.feature8: ternary;
        }
        actions = {
            set_code8;
            NoAction;
        }
        size = FEATURE_TABLE_SIZE;
        default_action = NoAction();
    }

	action set_code9(bit<CODE_WIDTH> code) {
        hdr.class.code9 = code;
    }

    table f9 {
        key = {
            hdr.class.feature9: ternary;
        }
        actions = {
            set_code9;
            NoAction;
        }
        size = FEATURE_TABLE_SIZE;
        default_action = NoAction();
    }

	action set_code10(bit<CODE_WIDTH> code) {
        hdr.class.code10 = code;
    }

    table f10 {
        key = {
            hdr.class.feature10: ternary;
        }
        actions = {
            set_code10;
            NoAction;
        }
        size = FEATURE_TABLE_SIZE;
        default_action = NoAction();
    }

	action set_code11(bit<CODE_WIDTH> code) {
        hdr.class.code11 = code;
    }

    table f11 {
        key = {
            hdr.class.feature11: ternary;
        }
        actions = {
            set_code11;
            NoAction;
        }
        size = FEATURE_TABLE_SIZE;
        default_action = NoAction();
    }

	action set_code12(bit<CODE_WIDTH> code) {
        hdr.class.code12 = code;
    }

    table f12 {
        key = {
            hdr.class.feature12: ternary;
        }
        actions = {
            set_code12;
            NoAction;
        }
        size = FEATURE_TABLE_SIZE;
        default_action = NoAction();
    }

    action set_leaf(bit<8> leaf) {
        hdr.class.leaf = leaf;
  }

    table leaf_table {
        key = {
            hdr.class.code1: ternary;
            hdr.class.code2: ternary;
            hdr.class.code3: ternary;
            hdr.class.code4: ternary;
            hdr.class.code5: ternary;
            hdr.class.code6: ternary;
            hdr.class.code7: ternary;
            hdr.class.code8: ternary;
            hdr.class.code9: ternary;
            hdr.class.code10: ternary;
            hdr.class.code11: ternary;
            hdr.class.code12: ternary;

        }
        actions = {
            set_leaf;
            NoAction;
        }
        size = LEAF_TABLE_SIZE;
        default_action = NoAction();
    }


    apply {
        f1.apply();
        f2.apply();
        f3.apply();
        f4.apply();
        f5.apply();
        f6.apply();
        f7.apply();
        f8.apply();
        f9.apply();
        f10.apply();
        f11.apply();
        f12.apply();
        leaf_table.apply();

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