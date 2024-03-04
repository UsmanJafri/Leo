import argparse

def int_to_binary_str(n, width):
	binary = ''
	i = 1 << (width - 1)
	while i > 0:
		if (n & i) != 0:
			binary += '1'
		else :
			binary += '0'

		i = i // 2
	return binary
			
def collapse_wildcard_pair(a, b, width):
	a = list(a)
	num_match = 0
	wildcard_ind = -1
	for i in range(len(a) -1, -1, -1):
		if wildcard_ind == -1 and a[i] != b[i]:
			wildcard_ind = i
		if a[i] == b[i]:
			num_match += 1
	
	if num_match == (width - 1) and wildcard_ind != -1:
		a[wildcard_ind] = '*'
		return ''.join(a)
	return None

def collapse_adjacent(strs, width):
	i = 0
	j = 1
	collapsed_last_round = False
	while len(strs) > 1:
		s = strs[i]
		s2 = strs[j]
		collapsed = collapse_wildcard_pair(s, s2, width)
		if collapsed:
			strs.remove(s)
			strs.remove(s2)
			strs.insert(i, collapsed)
			collapsed_last_round = True
		else:
			i += 1
			j += 1

		if j >= len(strs):
			if collapsed_last_round:
				i = 0
				j = 1
				collapsed_last_round = False
			else:
				break

	return strs

def tcam_rules_range(lower, upper, width):
	numbers_less_than = []
	for i in range(lower, upper + 1):
		numbers_less_than.append(int_to_binary_str(i, width))

	return collapse_adjacent(numbers_less_than, width)

def special_example_split_largest_into_halves(lower, upper, num_splits):
	if num_splits < 1:
		return None

	config = [(lower, lower), (1, upper)]
	for s in range(num_splits - 1):
		max_split_ind = -1
		max_split = -1
		for i in range(len(config)):
			size = config[i][1] - config[i][0]
			if size > max_split:
				max_split_ind = i
				max_split = size

		max_split = int(max_split / 2)

		max_split_upper = config[max_split_ind][1]
		config[max_split_ind] = (config[max_split_ind][0], config[max_split_ind][0] + max_split)
		new_split = (config[max_split_ind][1] + 1, max_split_upper)
		config.insert(max_split_ind + 1, new_split)

	return config

def main():
	parser = argparse.ArgumentParser(
		description='This program generates the worst-case feature table split for IIsy using TCAM.')
	
	parser.add_argument('--width', type=int, required=True, help='Feature width (number of bits)')
	parser.add_argument('--upper_lim', type=int, required=True, help='Maximum feature value')
	parser.add_argument('--leaves', type=int, required=True, help='Number of leaves in the tree.')
	args = parser.parse_args()
	
	if args.upper_lim > (2 ** args.width) - 1:
		args.upper_lim = (2 ** args.width) - 1

	lower = 0
	splits = args.leaves - 1

	print('{0:22} | {1:15} | {2}'.format('Leaf Range', '# of TCAM rules', 'TCAM Rules'))
	config = special_example_split_largest_into_halves(lower, args.upper_lim, splits)
	breakdown = ''
	total = 0
	maxx = 0
	for split in config:
		tcam = tcam_rules_range(split[0], split[1], args.width)
		breakdown += "{0:6} >= AND <= {1:5} | {2:15} | {3}\n".format(split[0], split[1], len(tcam), str(tcam))
		total += len(tcam)
		if len(tcam) > maxx:
			maxx = len(tcam)

	print(breakdown)
	print('Total rules:', total)
	print('Total rules exluding largest split (as default rule):', (total - maxx))
	print('=============================================================================================')

if __name__ == '__main__':
	main()