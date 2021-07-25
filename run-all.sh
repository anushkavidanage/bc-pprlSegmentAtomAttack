# First name with diff numbers of hash functions (50%, 25%, 12.5% full)
#
python bf-segment-attack.py 2 RH opt 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [3] [50,25,10,5,2,1] 1000
python bf-segment-attack.py 2 RH opt_half 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [3] [50,25,10,5,2,1] 1000
python bf-segment-attack.py 2 RH opt_quarter 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [3] [50,25,10,5,2,1] 1000

# Last name with diff numbers of hash functions (50%, 25%, 12.5% full)
#
python bf-segment-attack.py 2 RH opt 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [5] [50,25,10,5,2,1] 1000
python bf-segment-attack.py 2 RH opt_half 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [5] [50,25,10,5,2,1] 1000
python bf-segment-attack.py 2 RH opt_quarter 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [5] [50,25,10,5,2,1] 1000

# First and last name with diff numbers of hash functions (50%, 25%, 12.5% full)
#
python bf-segment-attack.py 2 RH opt 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [3,5] [50,25,10,5,2,1] 1000
python bf-segment-attack.py 2 RH opt_half 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [3,5] [50,25,10,5,2,1] 1000
python bf-segment-attack.py 2 RH opt_quarter 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [3,5] [50,25,10,5,2,1] 1000

# Street address with diff numbers of hash functions (50%, 25%, 12.5% full)
#
python bf-segment-attack.py 2 RH opt 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [11] [50,25,10,5,2,1] 1000
python bf-segment-attack.py 2 RH opt_half 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [11] [50,25,10,5,2,1] 1000
python bf-segment-attack.py 2 RH opt_quarter 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [11] [50,25,10,5,2,1] 1000

# First and last name, and street address with diff numbers of hash functions (50%, 25%, 12.5% full)
#
python bf-segment-attack.py 2 RH opt 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [3,5,11] [50,25,10,5,2,1] 1000
python bf-segment-attack.py 2 RH opt_half 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [3,5,11] [50,25,10,5,2,1] 1000
python bf-segment-attack.py 2 RH opt_quarter 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [3,5,11] [50,25,10,5,2,1] 1000
