def main():
    NUM_FEATURES = 9
    BITS_BUDGET = 57
    
    print('NUM FEATURES =', NUM_FEATURES, '| BITS BUDGET =', BITS_BUDGET)
    print('---')
    
    for i in range(NUM_FEATURES, -1, -1):
        max_use = 0
        max_config = None
        for j in range(0, NUM_FEATURES + 1):
            bits_used = (16 * i) + (8 * j)
            if i + j <= NUM_FEATURES: 
                if bits_used <= BITS_BUDGET:
                    if bits_used > max_use:
                        max_use = bits_used
                        max_config = (i, j)
        if max_use:          
            print('16-bit x', max_config[0], '| 8-bit x ', max_config[1], '| Use =', max_use, '/', BITS_BUDGET)

if __name__ == '__main__':
    main()