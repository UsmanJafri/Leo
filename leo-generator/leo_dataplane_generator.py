from leo_sram import leo_sram_gen
from leo_tcam import leo_tcam_gen

import argparse
import math

def main():
	parser = argparse.ArgumentParser(
		description='This program generates P4 code for Leo SRAM/TCAM for a target tree class.')
	
	grouped_args = parser.add_mutually_exclusive_group(required=True)
	grouped_args.add_argument('--sram', action='store_true', help='Use SRAM memory.')
	grouped_args.add_argument('--tcam', action='store_true', help='Use TCAM memory.')
	
	parser.add_argument('--filename', type=str, required=True, help='The output file name containing generated P4 code.')
	parser.add_argument('--sub_tree', type=int, required=True, help='Depth of sub-tree (2 = 3 nodes in a layer, 3 = 7 nodes in a layer, etc.)')
	parser.add_argument('--depth', type=int, required=True, help='The depth of the tree class (Excluding leaf layer).')
	parser.add_argument('--features', type=int, required=True, help='The number of features supported in the tree class.')
	parser.add_argument('--leaf_limit', type=int, default=0, help='If the tree class has a limit on the number of leaves (Exclude this argument if no limit).')
	parser.add_argument('--transient', action='store_true', help='Enable support for transient state during runtime tree updates.')
	args = parser.parse_args()

	layers = int(math.ceil(args.depth / args.sub_tree))

	if args.tcam:
		code = leo_tcam_gen(args.sub_tree, layers, args.features, args.leaf_limit, args.transient)
	elif args.sram:
		code = leo_sram_gen(args.sub_tree, layers, args.features, args.transient)

	f = open(args.filename, 'w')
	f.writelines(code)
	f.close()


if __name__ == '__main__':
	main()