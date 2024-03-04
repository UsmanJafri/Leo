import math
import argparse

def proposition_1_example(n, d, k):
	num_leaves = 2 ** d
	feature_table_size = k - math.ceil((k / num_leaves))
	leaf_table_size = math.ceil((num_leaves - 1) / num_leaves * ((((num_leaves - 1) / n) + 1) ** n))
	print('Feature table size (each):', feature_table_size)
	print('Leaf table size:', leaf_table_size)
	print('Total size:', (n * feature_table_size) + leaf_table_size)

def proposition_2_depth(n, k):
	return n +  math.ceil(math.log2(k))

def proposition_2_num_leaf_nodes(n, k):
	return (n ** 2) + (n * (k - 3)) + 2

def proposition_2_num_tcam_entries_An2(n, k):
	m = math.ceil(math.log2(k - 1))
	return m ** (n - 1)

def proposition_2_num_sram_entries_An2(n, k):
	return (k - 1) ** (n - 1)

def proposition_2_num_sram_total(n, N, k):
	if n == 1:
		return (N * (k - 1))

	total = 0
	for n_curr in range(2, n + 1): #[2 to n-1]
		total += (k - 1) ** n_curr

	for n_curr in range(2, n):
		total += (k - 1) ** 2
	
	return total + proposition_2_num_sram_total(n - 1, N, k)

def proposition_2_num_tcam_total(n, N, k):
	if n == 1:
		return (N * (k - 1))

	total = 0
	for n_curr in range(2, n + 1): #[2 to n-1]
		total += math.ceil(math.log2((k - 1))) ** n_curr

	for n_curr in range(2, n):
		total += math.ceil(math.log2((k - 1))) ** 2
	
	return total + proposition_2_num_tcam_total(n - 1, N, k)

def main():
	parser = argparse.ArgumentParser(
		description='This program implements the propositions 1 and 2 presented in the paper to model IIsy resource consumption.')

	subparsers = parser.add_subparsers(required=True, dest='subcommand')

	p1_args = subparsers.add_parser('p1', help='Apply proposition 1 model.')
	p2_args = subparsers.add_parser('p2', help='Apply proposition 2 model.')

	p1_args.add_argument('--n', type=int, required=True, help='The number of features.')
	p1_args.add_argument('--d', type=int, required=True, help='The depth of the tree (excluding leaf layer).')
	p1_args.add_argument('--k', type=int, required=True, help='The maximum feature value.')

	p2_args.add_argument('--filename', type=str, required=True, help='The output CSV file name containing the results of applying proposition 2 to a number of N, K combinations.')
	p2_args.add_argument('--N_max', type=int, required=True, help='The maximum number of features to explore up to. For example, N_max=5 will explore N=2,3,4,5')
	p2_args.add_argument('--K_power_max', type=int, required=True, help='The maximum feature value K to explore up to. Represented as a power of 2. For example, K_power_max=4 will explore K=3,7,15)')
	args = parser.parse_args()

	if args.subcommand == 'p1':
		proposition_1_example(args.n, args.d, args.k)
	elif args.subcommand == 'p2':
		f = open(args.filename, 'w')
		f.write('N (Number of features), K (Maximum feature value), Number of leaves, Depth, Number of A_{n-2} tcam entries, num_tcam_total (excl. default)\n')
		# n = 9
		for n in range(2, args.N_max + 1):
			for k_pow in range(2, args.K_power_max + 1):
				k = (2 ** k_pow) - 1
				f.write(str(n) + ',' + str(k) + ',' + str(proposition_2_num_leaf_nodes(n, k)) + ','+ str(proposition_2_depth(n, k)) + ',' + str(proposition_2_num_tcam_entries_An2(n, k)) + ',' + str(proposition_2_num_tcam_total(n, n, k) - (math.ceil(math.log2(k-1)) ** n)) + '\n')
				f.flush()

		f.close()

if __name__ == '__main__':
	main()