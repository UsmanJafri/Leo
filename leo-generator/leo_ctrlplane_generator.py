import math
import importlib 
import sys
from leo_templates import *

class InternalNode:
	def __init__(self, feature, constraint, depth):
		self.feature = feature
		self.constraint = constraint
		self.depth = depth
		self.left = None
		self.right = None

class LeafNode:
	def __init__(self, label, depth):
		self.label = label
		self.depth = depth

class Tree:
	def __init__(self, node):
		self.root = node

	def print_tree(self, node, level, prefix='ROOT'):
		if node is not None:
			if type(node) == InternalNode:
				print('|   ' * level + prefix, node.feature, node.constraint)
				if node.left is not None or node.right is not None:
					self.print_tree(node.left, level + 1, 'L   ')
					self.print_tree(node.right, level + 1, 'R   ')
			else:
				print('|   ' * level + prefix, node.label)

def parse_line(line):
	line = line.replace('|---', '|   ')
	depth = line.count('|   ')
	leaf = 'class' in line
	line = line.strip('|   ')
	line = line.split(' ')
	if leaf:
		label = int(line[1])
		return (leaf, depth, label)
	else:
		feature = line[0]
		condition = line[1]
		constraint = int(round(float(line[-1])))
		return (leaf, depth, feature, condition, constraint)

def find_my_right(node_lines, line_num, depth):
	for i in range(line_num, len(node_lines)):
		if node_lines[i][1] == depth:
			return i

	return None

def build_tree_recursive(node_lines, node, line_num):
	if line_num >= len(node_lines):
		return None

	tup = node_lines[line_num]
	if tup[0]:
		return None
	else:
		right_subtree_line_num = 1 + find_my_right(node_lines, line_num + 1, tup[1])
		right_node = node_lines[right_subtree_line_num]
		left_node = node_lines[line_num + 1]
		
		if left_node[0]:
			node.left = LeafNode(left_node[2], left_node[1])
		else:
			node.left = InternalNode(left_node[2], left_node[4], left_node[1])
			build_tree_recursive(node_lines, node.left, line_num + 1)

		if right_node[0]:
			node.right = LeafNode(right_node[2], right_node[1])
		else:
			node.right = InternalNode(right_node[2], right_node[4], right_node[1])
			build_tree_recursive(node_lines, node.right, right_subtree_line_num)
		
		return node

def build_tree_from_file(file):
	f = open(file, 'r')
	lines = f.readlines()
	f.close()

	nodes = []
	for line in lines:
		nodes.append(parse_line(line))

	root = InternalNode(nodes[0][2], nodes[0][4], nodes[0][1])
	build_tree_recursive(nodes, root, 0)
	tree = Tree(root)
	return tree

def find_k_children(node, k):
	children = []
	queue = [node]
	while len(queue) > 0:
		cur_node = queue.pop(0)
		children.append(cur_node)
		if len(children) == k:
			break

		if type(cur_node.left) == InternalNode:
			queue.append(cur_node.left)

		if type(cur_node.right) == InternalNode:
			queue.append(cur_node.right)

	return children

def sub_tree_splitter(root, K):
	bfs_sorted_nodes = []

	bfs_queue = [root]
	while len(bfs_queue) > 0:
		node = bfs_queue.pop(0)
		bfs_sorted_nodes.append(node)

		if type(node.left) == InternalNode:
			bfs_queue.append(node.left)
		if type(node.right) == InternalNode:
			bfs_queue.append(node.right)

	sub_groups = []
	while len(bfs_sorted_nodes) > 0:
		node = bfs_sorted_nodes[0]
		children = find_k_children(node, K)
		sub_groups.append(children)
		for c in children:
			bfs_sorted_nodes.remove(c)

	return sub_groups

def assign_rule_to_layers(sub_groups, subtree_layer_limits):
	assigned_layers = []
	for layer in range(1, len(subtree_layer_limits) + 1):
		layer_limit = subtree_layer_limits[layer - 1]
		print('Layer', layer, '| Available space:', layer_limit)
		curr_group = []
		for i in range(layer_limit):
			if len(sub_groups) != 0:
				rule = sub_groups.pop(0)
				curr_group.append(rule)
				for r in rule:
					print(r.feature, r.constraint, end=', '	)
				print()

		assigned_layers.append((layer, curr_group))

	if len(sub_groups) > 0:
		print('Error: Not all rules were assigned to a layer')

	return assigned_layers

def generate_runtime_code(layers, k):
	for layer in layers:
		for alu in range(1, k + 1):
			clear_table = clear_table_t.substitute(layer_id=layer[0], alu=alu)
			print(clear_table)

def main():	
	filename = 'tree-example.txt'
	k = 2
	num_layers = 3

	sys.path.append('..')
	leo_resource_model = importlib.import_module('leo.resource-model')

	alu_config = [k] * num_layers
	subtree_layer_limits = leo_resource_model.leo_model(alu_config, False, False)
	subtree_layer_limits = subtree_layer_limits[:-1]

	tree = build_tree_from_file(filename)
	sub_groups = sub_tree_splitter(tree.root, k)
	layers = assign_rule_to_layers(sub_groups, subtree_layer_limits)
	generate_runtime_code(layers, k)

if __name__ == '__main__':
	main()