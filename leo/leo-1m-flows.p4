
#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

const bit<8> FWD_PORT = 5;
const bit<8> BWD_PORT = 7;


#define KEY_SIZE 20
#define FEATURE_WIDTH 16
#define FEATURE_WIDTH_8 8
#define NUM_REGISTERS 188416
#define NUM_REGISTERS_8 376832
#define NUM_REGISTERS_ONE_STAGE 114688
#define NUM_REGISTERS_65K 65536
#define LEAF_ID_WIDTH 16

header leo_h {
    bit<8> state_group;
    bit<KEY_SIZE> state_index;
    bit<12> padding;
    bit<8> ingress_port;
    bit<8> pkt_len_div64;
    bit<FEATURE_WIDTH> feature_1;
    bit<FEATURE_WIDTH> feature_2;
    bit<FEATURE_WIDTH> feature_3;
    bit<FEATURE_WIDTH> feature_4;
    bit<FEATURE_WIDTH> feature_5;
	bit<FEATURE_WIDTH> alu_1_input;
	bit<FEATURE_WIDTH> alu_1_input_B;
	bit<FEATURE_WIDTH> alu_2_input;
	bit<FEATURE_WIDTH> alu_2_input_B;
	bit<FEATURE_WIDTH> alu_3_input;
	bit<FEATURE_WIDTH> alu_3_input_B;
	bit<LEAF_ID_WIDTH> leaf;
	bit<LEAF_ID_WIDTH> layer_1_result;
	bit<LEAF_ID_WIDTH> layer_2_result;
	bit<LEAF_ID_WIDTH> layer_3_result;
	bit<LEAF_ID_WIDTH> layer_4_result;
}

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
typedef bit<8> ip_protocol_t;

const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
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

header resubmit_header_t {
	bit<8>  type;
	bit<8> leo_class_id;
	}

struct header_t {
	ethernet_h ethernet;
	ipv4_h ipv4;
	tcp_h tcp;
	leo_h leo;
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
	   transition parse_leo_hdr;
	}

	state parse_leo_hdr {
	   pkt.extract(hdr.leo);
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
		pkt.emit(hdr.leo);
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

	Hash<bit<KEY_SIZE>>(HashAlgorithm_t.CRC32) crc32;

    action hash_packet(ipv4_addr_t ipAddr1, ipv4_addr_t ipAddr2, bit<16> port1, bit<16> port2, bit<8> proto) {
        hdr.leo.state_index = crc32.get({ipAddr1,
                                ipAddr2,
                                port1,
                                port2,
                                proto});
    }

	action set_state_group_0() {
		hdr.leo.state_group = 0;
	}

	action set_state_group_1_16bit() {
		hdr.leo.state_group = 1;
        hdr.leo.state_index = hdr.leo.state_index - 188416;
	}

	action set_state_group_1_8bit() {
		hdr.leo.state_group = 1;
        hdr.leo.state_index = hdr.leo.state_index - 376832;
	}

	action set_state_group_2_16bit() {
		hdr.leo.state_group = 2;
        hdr.leo.state_index = hdr.leo.state_index - 376832;
	}

	action set_state_group_2_8bit() {
		hdr.leo.state_group = 2;
        hdr.leo.state_index = hdr.leo.state_index - 565248;
	}

	action set_state_group_3_16bit() {
		hdr.leo.state_group = 3;
        hdr.leo.state_index = hdr.leo.state_index - 565248;
    }

	action set_state_group_3_8bit() {
		hdr.leo.state_group = 3;
        hdr.leo.state_index = hdr.leo.state_index - 753664;
	}

	table state_group_decider {
		key = {
			hdr.leo.state_index : range;
		}
		actions = {
		    set_state_group_0;
            set_state_group_1_16bit;
            set_state_group_1_8bit;
            set_state_group_2_16bit;
            set_state_group_2_8bit;
            set_state_group_3_16bit;
            set_state_group_3_8bit;
			NoAction;
		}
		size = 1000;
		default_action = NoAction();
	}

	Register<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>>(NUM_REGISTERS_8) bwd_packet_length_min;
	RegisterAction<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(bwd_packet_length_min) bwd_packet_length_min_update = {
        void apply(inout bit<FEATURE_WIDTH_8> value, out bit<FEATURE_WIDTH> read_value){
            if (hdr.leo.ingress_port == BWD_PORT) {
                if (hdr.leo.pkt_len_div64 < value) {
                    value = hdr.leo.pkt_len_div64;  
                }
            }
			read_value = 8w0 ++ value;
        }
    };

	Register<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>>(NUM_REGISTERS_8) fwd_segment_size_min;
	RegisterAction<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(fwd_segment_size_min) fwd_segment_size_min_update = {
        void apply(inout bit<FEATURE_WIDTH_8> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == FWD_PORT) {
                if ((hdr.leo.pkt_len_div64 - 54) < value) {
                    value = hdr.leo.pkt_len_div64 - 54;
                }
			}
			read_value = 8w0 ++ value;
        }
    };

	Register<bit<FEATURE_WIDTH>, bit<KEY_SIZE>>(NUM_REGISTERS) bwd_flow_size;
	RegisterAction<bit<FEATURE_WIDTH>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(bwd_flow_size) bwd_flow_size_update = {
        void apply(inout bit<FEATURE_WIDTH> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == BWD_PORT) {
                value = value + (8w0 ++ hdr.leo.pkt_len_div64);
			}
			read_value = value;
        }
    };

	Register<bit<FEATURE_WIDTH>, bit<KEY_SIZE>>(NUM_REGISTERS) fwd_flow_size;
	RegisterAction<bit<FEATURE_WIDTH>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(fwd_flow_size) fwd_flow_size_update = {
        void apply(inout bit<FEATURE_WIDTH> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == FWD_PORT) {
                value = value + (8w0 ++ hdr.leo.pkt_len_div64);
			}
			read_value = value;
        }
    };

	Register<bit<FEATURE_WIDTH>, bit<KEY_SIZE>>(NUM_REGISTERS) bwd_flow_size_B;
	RegisterAction<bit<FEATURE_WIDTH>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(bwd_flow_size_B) bwd_flow_size_B_update = {
        void apply(inout bit<FEATURE_WIDTH> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == BWD_PORT) {
                value = value + (8w0 ++ hdr.leo.pkt_len_div64);
			}
			read_value = value;
        }
    };

	Register<bit<FEATURE_WIDTH>, bit<KEY_SIZE>>(NUM_REGISTERS) fwd_flow_size_B;
	RegisterAction<bit<FEATURE_WIDTH>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(fwd_flow_size_B) fwd_flow_size_B_update = {
        void apply(inout bit<FEATURE_WIDTH> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == FWD_PORT) {
                value = value + (8w0 ++ hdr.leo.pkt_len_div64);
			}
			read_value = value;
        }
    };

	Register<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>>(NUM_REGISTERS_ONE_STAGE) bwd_packet_length_min_C;
	RegisterAction<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(bwd_packet_length_min_C) bwd_packet_length_min_C_update = {
        void apply(inout bit<FEATURE_WIDTH_8> value, out bit<FEATURE_WIDTH> read_value){
            if (hdr.leo.ingress_port == BWD_PORT) {
                if (hdr.leo.pkt_len_div64 < value) {
                    value = hdr.leo.pkt_len_div64;  
                }
            }
			read_value = 8w0 ++ value;
        }
    };

	Register<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>>(NUM_REGISTERS_ONE_STAGE) fwd_segment_size_min_C;
	RegisterAction<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(fwd_segment_size_min_C) fwd_segment_size_min_C_update = {
        void apply(inout bit<FEATURE_WIDTH_8> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == FWD_PORT) {
                if ((hdr.leo.pkt_len_div64 - 54) < value) {
                    value = hdr.leo.pkt_len_div64 - 54;
                }
			}
			read_value = 8w0 ++ value;
        }
    };

	Register<bit<FEATURE_WIDTH>, bit<KEY_SIZE>>(NUM_REGISTERS_ONE_STAGE) bwd_flow_size_C;
	RegisterAction<bit<FEATURE_WIDTH>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(bwd_flow_size_C) bwd_flow_size_C_update = {
        void apply(inout bit<FEATURE_WIDTH> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == BWD_PORT) {
                value = value + (8w0 ++ hdr.leo.pkt_len_div64);
			}
			read_value = value;
        }
    };

	Register<bit<FEATURE_WIDTH>, bit<KEY_SIZE>>(NUM_REGISTERS_ONE_STAGE) fwd_flow_size_C;
	RegisterAction<bit<FEATURE_WIDTH>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(fwd_flow_size_C) fwd_flow_size_C_update = {
        void apply(inout bit<FEATURE_WIDTH> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == FWD_PORT) {
                value = value + (8w0 ++ hdr.leo.pkt_len_div64);
			}
			read_value = value;
        }
    };

	Register<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>>(NUM_REGISTERS_8) bwd_packet_length_min_D;
	RegisterAction<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(bwd_packet_length_min_D) bwd_packet_length_min_D_update = {
        void apply(inout bit<FEATURE_WIDTH_8> value, out bit<FEATURE_WIDTH> read_value){
            if (hdr.leo.ingress_port == BWD_PORT) {
                if (hdr.leo.pkt_len_div64 < value) {
                    value = hdr.leo.pkt_len_div64;  
                }
            }
			read_value = 8w0 ++ value;
        }
    };

	Register<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>>(NUM_REGISTERS_8) fwd_segment_size_min_D;
	RegisterAction<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(fwd_segment_size_min_D) fwd_segment_size_min_D_update = {
        void apply(inout bit<FEATURE_WIDTH_8> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == FWD_PORT) {
                if ((hdr.leo.pkt_len_div64 - 54) < value) {
                    value = hdr.leo.pkt_len_div64 - 54;
                }
			}
			read_value = 8w0 ++ value;
        }
    };

	Register<bit<FEATURE_WIDTH>, bit<KEY_SIZE>>(NUM_REGISTERS) bwd_flow_size_D;
	RegisterAction<bit<FEATURE_WIDTH>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(bwd_flow_size_D) bwd_flow_size_D_update = {
        void apply(inout bit<FEATURE_WIDTH> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == BWD_PORT) {
                value = value + (8w0 ++ hdr.leo.pkt_len_div64);
			}
			read_value = value;
        }
    };

	Register<bit<FEATURE_WIDTH>, bit<KEY_SIZE>>(NUM_REGISTERS) fwd_flow_size_D;
	RegisterAction<bit<FEATURE_WIDTH>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(fwd_flow_size_D) fwd_flow_size_D_update = {
        void apply(inout bit<FEATURE_WIDTH> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == FWD_PORT) {
                value = value + (8w0 ++ hdr.leo.pkt_len_div64);
			}
			read_value = value;
        }
    };

	Register<bit<FEATURE_WIDTH>, bit<KEY_SIZE>>(NUM_REGISTERS) bwd_flow_size_E;
	RegisterAction<bit<FEATURE_WIDTH>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(bwd_flow_size_E) bwd_flow_size_E_update = {
        void apply(inout bit<FEATURE_WIDTH> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == BWD_PORT) {
                value = value + (8w0 ++ hdr.leo.pkt_len_div64);
			}
			read_value = value;
        }
    };

	Register<bit<FEATURE_WIDTH>, bit<KEY_SIZE>>(NUM_REGISTERS) fwd_flow_size_E;
	RegisterAction<bit<FEATURE_WIDTH>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(fwd_flow_size_E) fwd_flow_size_E_update = {
        void apply(inout bit<FEATURE_WIDTH> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == FWD_PORT) {
                value = value + (8w0 ++ hdr.leo.pkt_len_div64);
			}
			read_value = value;
        }
    };

	Register<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>>(NUM_REGISTERS_ONE_STAGE) bwd_packet_length_min_F;
	RegisterAction<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(bwd_packet_length_min_F) bwd_packet_length_min_F_update = {
        void apply(inout bit<FEATURE_WIDTH_8> value, out bit<FEATURE_WIDTH> read_value){
            if (hdr.leo.ingress_port == BWD_PORT) {
                if (hdr.leo.pkt_len_div64 < value) {
                    value = hdr.leo.pkt_len_div64;  
                }
            }
			read_value = 8w0 ++ value;
        }
    };

	Register<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>>(NUM_REGISTERS_ONE_STAGE) fwd_segment_size_min_F;
	RegisterAction<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(fwd_segment_size_min_F) fwd_segment_size_min_F_update = {
        void apply(inout bit<FEATURE_WIDTH_8> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == FWD_PORT) {
                if ((hdr.leo.pkt_len_div64 - 54) < value) {
                    value = hdr.leo.pkt_len_div64 - 54;
                }
			}
			read_value = 8w0 ++ value;
        }
    };

	Register<bit<FEATURE_WIDTH>, bit<KEY_SIZE>>(NUM_REGISTERS_ONE_STAGE) bwd_flow_size_F;
	RegisterAction<bit<FEATURE_WIDTH>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(bwd_flow_size_F) bwd_flow_size_F_update = {
        void apply(inout bit<FEATURE_WIDTH> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == BWD_PORT) {
                value = value + (8w0 ++ hdr.leo.pkt_len_div64);
			}
			read_value = value;
        }
    };

	Register<bit<FEATURE_WIDTH>, bit<KEY_SIZE>>(NUM_REGISTERS_ONE_STAGE) fwd_flow_size_F;
	RegisterAction<bit<FEATURE_WIDTH>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(fwd_flow_size_F) fwd_flow_size_F_update = {
        void apply(inout bit<FEATURE_WIDTH> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == FWD_PORT) {
                value = value + (8w0 ++ hdr.leo.pkt_len_div64);
			}
			read_value = value;
        }
    };

	Register<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>>(NUM_REGISTERS_65K) bwd_packet_length_min_G;
	RegisterAction<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(bwd_packet_length_min_G) bwd_packet_length_min_G_update = {
        void apply(inout bit<FEATURE_WIDTH_8> value, out bit<FEATURE_WIDTH> read_value){
            if (hdr.leo.ingress_port == BWD_PORT) {
                if (hdr.leo.pkt_len_div64 < value) {
                    value = hdr.leo.pkt_len_div64;  
                }
            }
			read_value = 8w0 ++ value;
        }
    };

	Register<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>>(NUM_REGISTERS_65K) fwd_segment_size_min_G;
	RegisterAction<bit<FEATURE_WIDTH_8>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(fwd_segment_size_min_G) fwd_segment_size_min_G_update = {
        void apply(inout bit<FEATURE_WIDTH_8> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == FWD_PORT) {
                if ((hdr.leo.pkt_len_div64 - 54) < value) {
                    value = hdr.leo.pkt_len_div64 - 54;
                }
			}
			read_value = 8w0 ++ value;
        }
    };

	Register<bit<FEATURE_WIDTH>, bit<KEY_SIZE>>(NUM_REGISTERS_65K) bwd_flow_size_G;
	RegisterAction<bit<FEATURE_WIDTH>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(bwd_flow_size_G) bwd_flow_size_G_update = {
        void apply(inout bit<FEATURE_WIDTH> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == BWD_PORT) {
                value = value + (8w0 ++ hdr.leo.pkt_len_div64);
			}
			read_value = value;
        }
    };

	Register<bit<FEATURE_WIDTH>, bit<KEY_SIZE>>(NUM_REGISTERS_65K) fwd_flow_size_G;
	RegisterAction<bit<FEATURE_WIDTH>, bit<KEY_SIZE>, bit<FEATURE_WIDTH>>(fwd_flow_size_G) fwd_flow_size_G_update = {
        void apply(inout bit<FEATURE_WIDTH> value, out bit<FEATURE_WIDTH> read_value){
			if (hdr.leo.ingress_port == FWD_PORT) {
                value = value + (8w0 ++ hdr.leo.pkt_len_div64);
			}
			read_value = value;
        }
    };

	apply {
		if (hdr.ipv4.isValid()) {
			ipv4_exact.apply();
		}

        hdr.leo.pkt_len_div64 = (hdr.ipv4.total_len >> 6)[7:0];
        hdr.leo.ingress_port = ig_intr_md.ingress_port[7:0];
        hdr.leo.feature_5 = hdr.tcp.dst_port;

		hash_packet(hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port, hdr.ipv4.protocol);
        state_group_decider.apply();

        if (hdr.leo.state_group == 0) {
            hdr.leo.feature_1 = bwd_packet_length_min_update.execute(hdr.leo.state_index);
            hdr.leo.feature_2 = fwd_segment_size_min_update.execute(hdr.leo.state_index);
            hdr.leo.feature_3 = bwd_flow_size_update.execute(hdr.leo.state_index);
            hdr.leo.feature_4 = fwd_flow_size_update.execute(hdr.leo.state_index);
        } else if (hdr.leo.state_group == 1) {
            hdr.leo.feature_3 = bwd_flow_size_B_update.execute(hdr.leo.state_index);
            hdr.leo.feature_4 = fwd_flow_size_B_update.execute(hdr.leo.state_index);
        } else if (hdr.leo.state_group == 2) {
            hdr.leo.feature_1 = bwd_packet_length_min_C_update.execute(hdr.leo.state_index);
            hdr.leo.feature_2 = fwd_segment_size_min_C_update.execute(hdr.leo.state_index);
            hdr.leo.feature_3 = bwd_flow_size_C_update.execute(hdr.leo.state_index);
            hdr.leo.feature_4 = fwd_flow_size_C_update.execute(hdr.leo.state_index);
		} else if (hdr.leo.state_group == 3) {
            hdr.leo.feature_1 = bwd_packet_length_min_D_update.execute(hdr.leo.state_index);
            hdr.leo.feature_2 = fwd_segment_size_min_D_update.execute(hdr.leo.state_index);
            hdr.leo.feature_3 = bwd_flow_size_D_update.execute(hdr.leo.state_index);
            hdr.leo.feature_4 = fwd_flow_size_D_update.execute(hdr.leo.state_index);
        } else if (hdr.leo.state_group == 4) {
            hdr.leo.feature_3 = bwd_flow_size_E_update.execute(hdr.leo.state_index);
            hdr.leo.feature_4 = fwd_flow_size_E_update.execute(hdr.leo.state_index);
        } else if (hdr.leo.state_group == 5) {
            hdr.leo.feature_1 = bwd_packet_length_min_F_update.execute(hdr.leo.state_index);
            hdr.leo.feature_2 = fwd_segment_size_min_F_update.execute(hdr.leo.state_index);
            hdr.leo.feature_3 = bwd_flow_size_F_update.execute(hdr.leo.state_index);
            hdr.leo.feature_4 = fwd_flow_size_F_update.execute(hdr.leo.state_index);
        } else if (hdr.leo.state_group == 6) {
            hdr.leo.feature_1 = bwd_packet_length_min_G_update.execute(hdr.leo.state_index);
            hdr.leo.feature_2 = fwd_segment_size_min_G_update.execute(hdr.leo.state_index);
            hdr.leo.feature_3 = bwd_flow_size_G_update.execute(hdr.leo.state_index);
            hdr.leo.feature_4 = fwd_flow_size_G_update.execute(hdr.leo.state_index);
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
	   transition parse_leo_hdr;
	}

	state parse_leo_hdr {
	   pkt.extract(hdr.leo);
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

	action set_leaf(bit<LEAF_ID_WIDTH> leaf) {
		hdr.leo.leaf = leaf;
	}

	action set_1_1_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_1_input = hdr.leo.feature_1 + constraint;
	}

	action set_1_1_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_1_input = hdr.leo.feature_2 + constraint;
	}

	action set_1_1_feature3(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_1_input = hdr.leo.feature_3 + constraint;
	}

	action set_1_1_feature4(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_1_input = hdr.leo.feature_4 + constraint;
	}

	action set_1_1_feature5(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_1_input = hdr.leo.feature_5 + constraint;
	}

	table layer_1_1 {
		key = {
			hdr.ipv4.version : ternary;
		}
		actions = {
			set_1_1_feature1;
			set_1_1_feature2;
			set_1_1_feature3;
			set_1_1_feature4;
			set_1_1_feature5;
			NoAction;
		}
		size = 1;
		default_action = NoAction();
	}

	action set_1_2_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input = hdr.leo.feature_1 + constraint;
	}

	action set_1_2_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input = hdr.leo.feature_2 + constraint;
	}

	action set_1_2_feature3(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input = hdr.leo.feature_3 + constraint;
	}

	action set_1_2_feature4(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input = hdr.leo.feature_4 + constraint;
	}

	action set_1_2_feature5(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input = hdr.leo.feature_5 + constraint;
	}

	table layer_1_2 {
		key = {
			hdr.ipv4.version : ternary;
		}
		actions = {
			set_1_2_feature1;
			set_1_2_feature2;
			set_1_2_feature3;
			set_1_2_feature4;
			set_1_2_feature5;
			NoAction;
		}
		size = 1;
		default_action = NoAction();
	}

	action set_1_3_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input = hdr.leo.feature_1 + constraint;
	}

	action set_1_3_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input = hdr.leo.feature_2 + constraint;
	}

	action set_1_3_feature3(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input = hdr.leo.feature_3 + constraint;
	}

	action set_1_3_feature4(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input = hdr.leo.feature_4 + constraint;
	}

	action set_1_3_feature5(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input = hdr.leo.feature_5 + constraint;
	}

	table layer_1_3 {
		key = {
			hdr.ipv4.version : ternary;
		}
		actions = {
			set_1_3_feature1;
			set_1_3_feature2;
			set_1_3_feature3;
			set_1_3_feature4;
			set_1_3_feature5;
			NoAction;
		}
		size = 1;
		default_action = NoAction();
	}

	action set_2_1_feature1(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_1_result = result;
		hdr.leo.alu_1_input_B = hdr.leo.feature_1 + constraint;
	}

	action set_2_1_feature2(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_1_result = result;
		hdr.leo.alu_1_input_B = hdr.leo.feature_2 + constraint;
	}

	action set_2_1_feature3(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_1_result = result;
		hdr.leo.alu_1_input_B = hdr.leo.feature_3 + constraint;
	}

	action set_2_1_feature4(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_1_result = result;
		hdr.leo.alu_1_input_B = hdr.leo.feature_4 + constraint;
	}

	action set_2_1_feature5(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_1_result = result;
		hdr.leo.alu_1_input_B = hdr.leo.feature_5 + constraint;
	}

	table layer_2_1 {
		key = {
			hdr.leo.alu_1_input : ternary;
			hdr.leo.alu_2_input : ternary;
			hdr.leo.alu_3_input : ternary;
		}
		actions = {
		set_leaf;
			set_2_1_feature1;
			set_2_1_feature2;
			set_2_1_feature3;
			set_2_1_feature4;
			set_2_1_feature5;
			NoAction;
		}
		size = 4;
		default_action = NoAction();
	}

	action set_2_2_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input_B = hdr.leo.feature_1 + constraint;
	}

	action set_2_2_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input_B = hdr.leo.feature_2 + constraint;
	}

	action set_2_2_feature3(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input_B = hdr.leo.feature_3 + constraint;
	}

	action set_2_2_feature4(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input_B = hdr.leo.feature_4 + constraint;
	}

	action set_2_2_feature5(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input_B = hdr.leo.feature_5 + constraint;
	}

	table layer_2_2 {
		key = {
			hdr.leo.alu_1_input : ternary;
			hdr.leo.alu_2_input : ternary;
			hdr.leo.alu_3_input : ternary;
		}
		actions = {
			set_2_2_feature1;
			set_2_2_feature2;
			set_2_2_feature3;
			set_2_2_feature4;
			set_2_2_feature5;
			NoAction;
		}
		size = 4;
		default_action = NoAction();
	}

	action set_2_3_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input_B = hdr.leo.feature_1 + constraint;
	}

	action set_2_3_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input_B = hdr.leo.feature_2 + constraint;
	}

	action set_2_3_feature3(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input_B = hdr.leo.feature_3 + constraint;
	}

	action set_2_3_feature4(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input_B = hdr.leo.feature_4 + constraint;
	}

	action set_2_3_feature5(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input_B = hdr.leo.feature_5 + constraint;
	}

	table layer_2_3 {
		key = {
			hdr.leo.alu_1_input : ternary;
			hdr.leo.alu_2_input : ternary;
			hdr.leo.alu_3_input : ternary;
		}
		actions = {
			set_2_3_feature1;
			set_2_3_feature2;
			set_2_3_feature3;
			set_2_3_feature4;
			set_2_3_feature5;
			NoAction;
		}
		size = 4;
		default_action = NoAction();
	}

	action set_3_1_feature1(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_2_result = result;
		hdr.leo.alu_1_input = hdr.leo.feature_1 + constraint;
	}

	action set_3_1_feature2(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_2_result = result;
		hdr.leo.alu_1_input = hdr.leo.feature_2 + constraint;
	}

	action set_3_1_feature3(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_2_result = result;
		hdr.leo.alu_1_input = hdr.leo.feature_3 + constraint;
	}

	action set_3_1_feature4(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_2_result = result;
		hdr.leo.alu_1_input = hdr.leo.feature_4 + constraint;
	}

	action set_3_1_feature5(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_2_result = result;
		hdr.leo.alu_1_input = hdr.leo.feature_5 + constraint;
	}

	table layer_3_1 {
		key = {
			hdr.leo.layer_1_result : ternary;
			hdr.leo.alu_1_input_B : ternary;
			hdr.leo.alu_2_input_B : ternary;
			hdr.leo.alu_3_input_B : ternary;
		}
		actions = {
		set_leaf;
			set_3_1_feature1;
			set_3_1_feature2;
			set_3_1_feature3;
			set_3_1_feature4;
			set_3_1_feature5;
			NoAction;
		}
		size = 16;
		default_action = NoAction();
	}

	action set_3_2_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input = hdr.leo.feature_1 + constraint;
	}

	action set_3_2_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input = hdr.leo.feature_2 + constraint;
	}

	action set_3_2_feature3(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input = hdr.leo.feature_3 + constraint;
	}

	action set_3_2_feature4(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input = hdr.leo.feature_4 + constraint;
	}

	action set_3_2_feature5(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input = hdr.leo.feature_5 + constraint;
	}

	table layer_3_2 {
		key = {
			hdr.leo.layer_1_result : ternary;
			hdr.leo.alu_1_input_B : ternary;
			hdr.leo.alu_2_input_B : ternary;
			hdr.leo.alu_3_input_B : ternary;
		}
		actions = {
			set_3_2_feature1;
			set_3_2_feature2;
			set_3_2_feature3;
			set_3_2_feature4;
			set_3_2_feature5;
			NoAction;
		}
		size = 16;
		default_action = NoAction();
	}

	action set_3_3_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input = hdr.leo.feature_1 + constraint;
	}

	action set_3_3_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input = hdr.leo.feature_2 + constraint;
	}

	action set_3_3_feature3(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input = hdr.leo.feature_3 + constraint;
	}

	action set_3_3_feature4(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input = hdr.leo.feature_4 + constraint;
	}

	action set_3_3_feature5(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input = hdr.leo.feature_5 + constraint;
	}

	table layer_3_3 {
		key = {
			hdr.leo.layer_1_result : ternary;
			hdr.leo.alu_1_input_B : ternary;
			hdr.leo.alu_2_input_B : ternary;
			hdr.leo.alu_3_input_B : ternary;
		}
		actions = {
			set_3_3_feature1;
			set_3_3_feature2;
			set_3_3_feature3;
			set_3_3_feature4;
			set_3_3_feature5;
			NoAction;
		}
		size = 16;
		default_action = NoAction();
	}

	action set_4_1_feature1(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_3_result = result;
		hdr.leo.alu_1_input_B = hdr.leo.feature_1 + constraint;
	}

	action set_4_1_feature2(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_3_result = result;
		hdr.leo.alu_1_input_B = hdr.leo.feature_2 + constraint;
	}

	action set_4_1_feature3(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_3_result = result;
		hdr.leo.alu_1_input_B = hdr.leo.feature_3 + constraint;
	}

	action set_4_1_feature4(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_3_result = result;
		hdr.leo.alu_1_input_B = hdr.leo.feature_4 + constraint;
	}

	action set_4_1_feature5(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_3_result = result;
		hdr.leo.alu_1_input_B = hdr.leo.feature_5 + constraint;
	}

	table layer_4_1 {
		key = {
			hdr.leo.layer_2_result : ternary;
			hdr.leo.alu_1_input : ternary;
			hdr.leo.alu_2_input : ternary;
			hdr.leo.alu_3_input : ternary;
		}
		actions = {
		set_leaf;
			set_4_1_feature1;
			set_4_1_feature2;
			set_4_1_feature3;
			set_4_1_feature4;
			set_4_1_feature5;
			NoAction;
		}
		size = 64;
		default_action = NoAction();
	}

	action set_4_2_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input_B = hdr.leo.feature_1 + constraint;
	}

	action set_4_2_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input_B = hdr.leo.feature_2 + constraint;
	}

	action set_4_2_feature3(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input_B = hdr.leo.feature_3 + constraint;
	}

	action set_4_2_feature4(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input_B = hdr.leo.feature_4 + constraint;
	}

	action set_4_2_feature5(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input_B = hdr.leo.feature_5 + constraint;
	}

	table layer_4_2 {
		key = {
			hdr.leo.layer_2_result : ternary;
			hdr.leo.alu_1_input : ternary;
			hdr.leo.alu_2_input : ternary;
			hdr.leo.alu_3_input : ternary;
		}
		actions = {
			set_4_2_feature1;
			set_4_2_feature2;
			set_4_2_feature3;
			set_4_2_feature4;
			set_4_2_feature5;
			NoAction;
		}
		size = 64;
		default_action = NoAction();
	}

	action set_4_3_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input_B = hdr.leo.feature_1 + constraint;
	}

	action set_4_3_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input_B = hdr.leo.feature_2 + constraint;
	}

	action set_4_3_feature3(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input_B = hdr.leo.feature_3 + constraint;
	}

	action set_4_3_feature4(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input_B = hdr.leo.feature_4 + constraint;
	}

	action set_4_3_feature5(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input_B = hdr.leo.feature_5 + constraint;
	}

	table layer_4_3 {
		key = {
			hdr.leo.layer_2_result : ternary;
			hdr.leo.alu_1_input : ternary;
			hdr.leo.alu_2_input : ternary;
			hdr.leo.alu_3_input : ternary;
		}
		actions = {
			set_4_3_feature1;
			set_4_3_feature2;
			set_4_3_feature3;
			set_4_3_feature4;
			set_4_3_feature5;
			NoAction;
		}
		size = 64;
		default_action = NoAction();
	}

	action set_5_1_feature1(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_4_result = result;
		hdr.leo.alu_1_input = hdr.leo.feature_1 + constraint;
	}

	action set_5_1_feature2(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_4_result = result;
		hdr.leo.alu_1_input = hdr.leo.feature_2 + constraint;
	}

	action set_5_1_feature3(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_4_result = result;
		hdr.leo.alu_1_input = hdr.leo.feature_3 + constraint;
	}

	action set_5_1_feature4(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_4_result = result;
		hdr.leo.alu_1_input = hdr.leo.feature_4 + constraint;
	}

	action set_5_1_feature5(bit<LEAF_ID_WIDTH> result, bit<FEATURE_WIDTH> constraint) {
		hdr.leo.layer_4_result = result;
		hdr.leo.alu_1_input = hdr.leo.feature_5 + constraint;
	}

	table layer_5_1 {
		key = {
			hdr.leo.layer_3_result : ternary;
			hdr.leo.alu_1_input_B : ternary;
			hdr.leo.alu_2_input_B : ternary;
			hdr.leo.alu_3_input_B : ternary;
		}
		actions = {
		set_leaf;
			set_5_1_feature1;
			set_5_1_feature2;
			set_5_1_feature3;
			set_5_1_feature4;
			set_5_1_feature5;
			NoAction;
		}
		size = 256;
		default_action = NoAction();
	}

	action set_5_2_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input = hdr.leo.feature_1 + constraint;
	}

	action set_5_2_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input = hdr.leo.feature_2 + constraint;
	}

	action set_5_2_feature3(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input = hdr.leo.feature_3 + constraint;
	}

	action set_5_2_feature4(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input = hdr.leo.feature_4 + constraint;
	}

	action set_5_2_feature5(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_2_input = hdr.leo.feature_5 + constraint;
	}

	table layer_5_2 {
		key = {
			hdr.leo.layer_3_result : ternary;
			hdr.leo.alu_1_input_B : ternary;
			hdr.leo.alu_2_input_B : ternary;
			hdr.leo.alu_3_input_B : ternary;
		}
		actions = {
			set_5_2_feature1;
			set_5_2_feature2;
			set_5_2_feature3;
			set_5_2_feature4;
			set_5_2_feature5;
			NoAction;
		}
		size = 256;
		default_action = NoAction();
	}

	action set_5_3_feature1(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input = hdr.leo.feature_1 + constraint;
	}

	action set_5_3_feature2(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input = hdr.leo.feature_2 + constraint;
	}

	action set_5_3_feature3(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input = hdr.leo.feature_3 + constraint;
	}

	action set_5_3_feature4(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input = hdr.leo.feature_4 + constraint;
	}

	action set_5_3_feature5(bit<FEATURE_WIDTH> constraint) {
		hdr.leo.alu_3_input = hdr.leo.feature_5 + constraint;
	}

	table layer_5_3 {
		key = {
			hdr.leo.layer_3_result : ternary;
			hdr.leo.alu_1_input_B : ternary;
			hdr.leo.alu_2_input_B : ternary;
			hdr.leo.alu_3_input_B : ternary;
		}
		actions = {
			set_5_3_feature1;
			set_5_3_feature2;
			set_5_3_feature3;
			set_5_3_feature4;
			set_5_3_feature5;
			NoAction;
		}
		size = 256;
		default_action = NoAction();
	}

	table layer_6_1 {
		key = {
			hdr.leo.layer_4_result : ternary;
			hdr.leo.alu_1_input : ternary;
			hdr.leo.alu_2_input : ternary;
			hdr.leo.alu_3_input : ternary;
		}
		actions = {
			set_leaf;
			NoAction;
		}
		size = 1024;
		default_action = NoAction();
	}

	apply {
		layer_1_1.apply();
		layer_1_2.apply();
		layer_1_3.apply();
		layer_2_1.apply();
		layer_2_2.apply();
		layer_2_3.apply();
		layer_3_1.apply();
		layer_3_2.apply();
		layer_3_3.apply();
		layer_4_1.apply();
		layer_4_2.apply();
		layer_4_3.apply();
		layer_5_1.apply();
		layer_5_2.apply();
		layer_5_3.apply();
		layer_6_1.apply();
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
		pkt.emit(hdr.leo);
	}
}

Pipeline(SwitchIngressParser(),
		 SwitchIngress(),
		 SwitchIngressDeparser(),
		 SwitchEgressParser(),
		 SwitchEgress(),
		 SwitchEgressDeparser()) pipe;

Switch(pipe) main;
