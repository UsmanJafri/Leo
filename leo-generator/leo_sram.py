from leo_templates import *

def layer_gen(num_alus, num_features, layer_id, sub_tree, transient):
	code = []

	for a in range(1, num_alus + 1):

		# first ALU of layer 2 and layer responsible for setting leaf
		if a == 1 and layer_id > 1:
			actions_for_table = '\n\t\t\tset_leaf;'
		else:
			actions_for_table = ''

		for f in range(1, num_features + 1):
			# first ALU of layer 2 and layer responsible for compressing prev. layers into cell ID
			if a == 1 and layer_id > 1:
				action = mux_action_decl_with_result_t.substitute({'layer' : layer_id, 'alu' : a, 'feature' : f, 'layer_prev' : layer_id - 1})
			else:
				action = mux_action_decl_t.substitute({'layer' : layer_id, 'alu' : a, 'feature' : f})

			actions_for_table += mux_action_t.substitute({'layer' : layer_id, 'alu' : a, 'feature' : f})
			code.append(action)
		
		if layer_id == 1:
			keys = mux_key_t.substitute({'key_name' : 'tree_id', 'table_type' : 'exact'})
		else:
			keys = ''
			if transient and layer_id == 2:
				keys += mux_key_t.substitute({'key_name' : 'tree_id', 'table_type' : 'exact'})
			if layer_id > 2:
				keys += mux_key_t.substitute({'key_name' : 'layer_' + str(layer_id - 2) +  '_result', 'table_type' : 'exact'})

			for a2 in range(1, num_alus + 1):
				keys += mux_key_t.substitute({'key_name' : 'alu_' + str(a2) + '_result', 'table_type' : 'exact'})
	
		table_size = 2 ** ((sub_tree * layer_id) - sub_tree)
		if layer_id > 1:
			table_size = (2 ** num_alus) * (2 ** ((sub_tree * (layer_id - 1)) - sub_tree))

		if transient:
			table_size = table_size * 2

		table = mux_table_t.substitute({'layer' : layer_id, 'alu' : a, 'table_size' : int(table_size), 'actions': actions_for_table, 'keys' : keys})
		code.append(table)

	return code

def custom_hdrs_gen(num_layers, num_alus, num_features):
	features = ''
	for f in range(1, num_features + 1):
		features += '\tbit<FEATURE_WIDTH> feature_' + str(f) + ';\n'
	
	layer_results = ''
	for l in range(1, num_layers):
		layer_results += '\tbit<LEAF_ID_WIDTH> layer_' + str(l) + '_result;\n'

	alu_hdrs = ''
	for a in range(1, num_alus + 1):
		alu_hdrs += '\tbit<FEATURE_WIDTH> alu_' + str(a) + '_input;\n'
		alu_hdrs += '\tbit<FEATURE_WIDTH> alu_' + str(a) + '_result;\n'
	# if num_alus % 8 != 0:
	# 	pad = 8 - (num_alus % 8)
	# 	alu_hdrs += '\tbit<' + str(pad) + '> padding;\n'
		
	hdrs = custom_header_t.substitute({'hdrs' : layer_results + alu_hdrs + features})
	return hdrs
	
def apply_block_gen(num_layers, num_alus):
	layer_calls = ''
	for l in range(1, num_layers + 1):
		for a in range(1, num_alus + 1):
			layer_calls += '\t\tlayer_' + str(l) + '_' + str(a) + '.apply();\n'
		
		for a in range(1, num_alus + 1):
			layer_calls += '\t\tALU_' + str(a) + '_and();\n'

	layer_calls += '\t\tlayer_' + str(num_layers + 1) + '_1.apply();\n'
	apply_block = apply_t.substitute({'layer_apply' : layer_calls})
	return apply_block

def final_table_gen(num_layers, num_alus, sub_tree, transient):
	# If one layer only, no grand-father to match on
	if num_layers > 1:
		keys = mux_key_t.substitute({'key_name' : 'layer_' + str(num_layers - 1) +  '_result', 'table_type' : 'exact'})
	else:
		keys = ''

	# Add ALU results to key
	for a2 in range(1, num_alus + 1):
		keys += mux_key_t.substitute({'key_name' : 'alu_' + str(a2) + '_result', 'table_type' : 'exact'})
	
	table_size = 2 ** ((sub_tree * (num_layers + 1)) - sub_tree)
	table_size = (2 ** num_alus) * (2 ** ((sub_tree * num_layers) - sub_tree))

	if transient:
		table_size = table_size * 2

	final_table = mux_table_t.substitute({'layer' : num_layers + 1, 'alu' : '1', 'table_size' : int(table_size), 'actions': '\n\t\t\tset_leaf;', 'keys' : keys})
	return final_table

def leo_sram_gen(sub_tree, num_layers, num_features, transient):
	num_alus = (2 ** sub_tree) - 1

	alu_code = ''
	for a in range(1, num_alus + 1):
		alu = stateless_AND_alu_T.substitute({'alu' : a})
		alu_code += alu

	layers = []
	for l in range(1, num_layers + 1):
		layers += layer_gen(num_alus, num_features, l, sub_tree, transient)

	final_table = final_table_gen(num_layers, num_alus, sub_tree, transient)
	custom_hdrs = custom_hdrs_gen(num_layers, num_alus, num_features)
	apply_block = apply_block_gen(num_layers, num_alus)

	code = [std_headers] + [custom_hdrs] + [ingress_parser_deparser] + [egress_parser_deparser] + [alu_code] + layers + [final_table] + [apply_block] + [footer]
	return code