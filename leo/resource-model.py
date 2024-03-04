import argparse

def leo_model(alu_config, is_sram, transient, log=False):
	num_alu_layers = len(alu_config)
	single_table_sizes = []

	total_size = 0
	curr_layer_result_combos = 1
	prev_layer_tcam = 1
	curr_layer_tcam = 1

	if log:
		print('{:>12}  {:>12}  {:>12}'.format('Layer #', 'Single Table Size', 'Total Layer Size'))
	for l in range(1, num_alu_layers + 2):
		if l == num_alu_layers + 1:
			num_mux_next_layer = 1
		else:
			num_mux_next_layer = alu_config[l - 1]

		if l > 1:
			curr_layer_tcam = alu_config[l - 2] + 1
			if is_sram:
				curr_layer_result_combos = 2 ** alu_config[l - 2]
			else:
				curr_layer_result_combos = curr_layer_tcam
					
		single_table_size = curr_layer_result_combos * prev_layer_tcam
		layer_size = single_table_size * num_mux_next_layer
		if transient:
			layer_size = layer_size * 2
			single_table_size = single_table_size * 2

		total_size += layer_size

		single_table_sizes.append(single_table_size)
		if log:
			print('{:>12}  {:>12}  {:>12}'.format(l, single_table_size, layer_size))

		prev_layer_tcam = curr_layer_tcam * prev_layer_tcam

	if log:
		print('Total Size:', total_size)
	return single_table_sizes

# Rules in layer i of LEO
def R_i(i, L, R, K):
	if i == 1:
		return 1
	if L != 0:
		return min(L, R[i-1] * (K[i] + 1))
	else:
		return R[i-1] * (K[i] + 1)

def args_type_for_number_list(arg):
    try:
        return [int(num) for num in arg.split(',')]
    except ValueError:
        raise argparse.ArgumentTypeError('Invalid list of integers: "{}"'.format(arg))

if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description='This program prints out a breakdown of the table size in each compute Layer of Leo.')
	
	grouped_args = parser.add_mutually_exclusive_group(required=True)
	grouped_args.add_argument('--sram', action='store_true', help='Calculate memory usage for SRAM.')
	grouped_args.add_argument('--tcam', action='store_true', help='Calculate memory usage for TCAM.')

	parser.add_argument('--transient', action='store_true', help='Calculate memory use including the additional cost of support transient states during runtime updates.')
	parser.add_argument('--muxed_alu_config', type=args_type_for_number_list, required=True, help='A comma-separated list of integers representing the number of "Multiplexed ALUs" in each layer. E.g.: 3,3,1 represents a tree where 3 nodes (2 levels) are multiplexed in the first layer, 3 nodes (2 levels) are muxed in the second layer, and 1 node (1 level) is muxed in the third layer. A fourth leaf layer is automatically added.')
	args = parser.parse_args()
	
	if args.tcam:
		leo_model(args.muxed_alu_config, False, args.transient, True)
	elif args.sram:
		leo_model(args.muxed_alu_config, True, args.transient, True)

	# R = [1]
	# K = [0,3,3,3,3,3]
	# LEAF_LIMIT = 0
	
	# print('ALU config K =', K[1:])
	# print('Leaf Limit L =', LEAF_LIMIT)
	# print('{:>12}  {:>12}  {:>12}'.format('i', 'R_i / TCAM', 'SRAM'))

	# for i in range(1, len(K)):
	# 	R_i_val = R_i(i, LEAF_LIMIT, R, K)
	# 	SRAM = R_i(i-1, LEAF_LIMIT, R, K) * 2 ** (K[i-1])
	# 	print('{:>12}  {:>12}  {:>12}'.format(i, R_i_val, SRAM))
	# 	R.append(R_i_val)