# bf-segment-attack.py - An atom BF based attack on BF segments
#
# Peter Christen
#
# Contact: peter.christen@anu.edu.au
#
# School of Computing, The Australian National University, Canberra, ACT, 2600
# -----------------------------------------------------------------------------
#
# Copyright 2021 Australian National University and others.
# All Rights reserved.
#
# -----------------------------------------------------------------------------
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#
# =============================================================================

# An attack BF segments, assuming the adversary knows how BFs were encoded
#
# Peter Christen, July 2021
#
# Usage:
#   python bf-segment-attack.py [q] [hash_type] [num_hash_funct] [bf_len]
#                               [my_data_set_name] [ot_data_set_name]
#                               [rec_id_col] [col_sep] [header_line_flag]
#                               [attr_list] [bf_seg_perc_list]
#
# where:
# q                 is the length of q-grams to use
# hash_type         is either DH (double-hashing) or RH (random hashing)
# num_hash_funct    is a positive number, 'opt' (to fill BF 50% on average),
#                   'opt_half' (to fill BF 25% on average), or 'opt_quarter'
#                   (to fill BF 12.5% on average)
# bf_len            is the length of Bloom filters
#
# my_data_set_name  is the name of the CSV file to use for the data set of
#                   the database owner (where we have access to full BFs)
# ot_data_set_name  is the name of the CSV file to use for the data set of
#                   the other database owner (where we have access only to
#                   BF segments)
# rec_id_col        is the column in the CSV file containing record
#                   identifiers (assumed to be same in both data sets)
# col_sep           is the character to be used to separate fields in the
#                   input data sets
# header_line_flag  is a flag, set to True if the file has a header line
#                   with attribute (field) names
# attr_list         is the list of attributes to encode into BFs
#
# bf_seg_perc_list  is the list of BF segment percentages to be attacked
# num_bf_to_attack  is the number of BFs to be used in the attack, with
#                   possible valus 'all' or a positive integer value. This
#                   allows for faster testing.
#
# Example call (on laptop):
#
# python bf-segment-attack.py 2 RH 20 1000 ncvoter-20140619-temporal-balanced-ratio-1to1-a.csv.gz ncvoter-20140619-temporal-balanced-ratio-1to1-b.csv.gz 0 , True [5] [50,25,10,5,2,1]

NUM_MATCHES_TO_TRY = 1000  # or 'all'

# -----------------------------------------------------------------------------

# Outline of the attack on BF segments
#
# We generate atom BFs for all unique q-grams (setting the 1-bits for each
# q-gram individually). These atoms are the same across all DOs. Then for
# each BF we obtain from another DO, we check which q-gram can be encoded
# based on all its atom bits set to 1 in the segment.
# This gives us a set of q-grams that can be encoded into a BF segment, and
# from this we find the plain-text value which contains most of these q-grams.
#
# -----------------------------------------------------------------------------

import csv
import gzip
import hashlib
import math
import random
import sys
import time

import bitarray
import numpy

BF_HASH_FUNCT1 = hashlib.sha1
BF_HASH_FUNCT2 = hashlib.md5

random.seed(42)

# -----------------------------------------------------------------------------

def load_data_set_extract_q_grams(file_name, rec_id_col, use_attr_list,
                                  col_sep_char, header_line, q):
  """Load the given file, extract selected attributes, and convert each unique
     attribute value into a q-gram set.

     Return two dictionaries, one with attribute values as keys and their
     q-gram set as values. The second dictionary has q-grams as keys and for
     each a set of all the plain-text values that contain this q-gram.

     The function also returns the average number of q-grams per attribute
     value, and the set of all unique q-grams that occurred in any values.
     Also returns a string with the names of the encoded attributes.
  """

  start_time = time.time()

  if (file_name.endswith('gz')):
    f = gzip.open(file_name)
  else:
    f = open(file_name)

  csv_reader = csv.reader(f, delimiter=col_sep_char)

  print 'Load data set from file:', file_name
  print '  Attribute separator: %c' % (col_sep_char)
  if (header_line == True):
    header_list = csv_reader.next()
    print '  Header line:', header_list

  use_attr_name_list = []

  if (header_line == False):
    print '  Record identifier attribute number:', rec_id_col
  else:
    print '  Record identifier attribute:', header_list[rec_id_col]
    print '    Attributes to use:',
    for attr_num in use_attr_list:
      use_attr_name = header_list[attr_num]
      print use_attr_name,
      use_attr_name_list.append(use_attr_name)
    print
  print
  print '  Extract q-grams with q=%d' % (q)
  print

  encoded_attr_name_str = ';'.join(use_attr_name_list)

  qm1 = q-1  # Shorthand

  attr_val_q_gram_dict = {}
  q_gram_attr_val_dict = {}
  all_q_gram_set =       set()

  num_q_gram_per_attr_val_list = []  # To calculate statistics

  rec_num = 0

  for rec_list in csv_reader:
    rec_num += 1

    if (rec_num % 100000 == 0):
      time_used = time.time() - start_time
      print '  Processed %d records in %.3f sec (%.3f msec average)' % \
            (rec_num, time_used, 1000.0*time_used/rec_num)

    attr_val_list = []  # The attribute values to be converted into q-grams

    for attr_num in use_attr_list:
      attr_val_list.append(rec_list[attr_num].strip().lower())

    # Concatenate with whitespaces and keep as one string per record
    #
    attr_val = ' '.join(attr_val_list).strip()

    # Encode each attribute value once
    #
    if (attr_val not in attr_val_q_gram_dict):

      attr_q_gram_set = set([attr_val[i:i+q] for i in range(len(attr_val)-qm1)])

      if (len(attr_q_gram_set) > 0):

        # Keep the q-gram set for this attribute value
        #
        attr_val_q_gram_dict[attr_val] = attr_q_gram_set
        num_q_gram_per_attr_val_list.append(len(attr_q_gram_set))

        # Keep the attribute value for each of its q-grams
        #
        for q_gram in attr_q_gram_set:
          q_gram_attr_val_set = q_gram_attr_val_dict.get(q_gram, set())
          q_gram_attr_val_set.add(attr_val)
          q_gram_attr_val_dict[q_gram] = q_gram_attr_val_set

          all_q_gram_set.add(q_gram)  # And keep all unique q-grams

  time_used = time.time() - start_time
  print '  Processed %d records in %.2f sec (%.2f msec average)' % \
        (rec_num, time_used, 1000.0*time_used/rec_num)

  num_attr_val_q_gram_list = []
  for attr_val_set in q_gram_attr_val_dict.itervalues():
    num_attr_val_q_gram_list.append(len(attr_val_set))

  print
  print '  Found %d unique attribute values' % (len(attr_val_q_gram_dict))
  print
  print '  Number of attribute values per q-gram:'
  print '    Minimum: %d' % (min(num_attr_val_q_gram_list))
  print '    Average: %.1f' % (numpy.mean(num_attr_val_q_gram_list))
  print '    Median:  %d' % (numpy.median(num_attr_val_q_gram_list))
  print '    Maximum: %d' % (max(num_attr_val_q_gram_list))

  avr_num_q_gram = numpy.mean(num_q_gram_per_attr_val_list)

  print '  Average number of q-grams per attribte value: %.2f' % \
        (avr_num_q_gram)
  print '    Minimum and maximum number of q-grams: %d / %d' % \
        (min(num_q_gram_per_attr_val_list), max(num_q_gram_per_attr_val_list))
  print '  Total number of unique q-grams in all values: %d' % \
        (len(all_q_gram_set))
  print

  return attr_val_q_gram_dict, q_gram_attr_val_dict, avr_num_q_gram, \
         all_q_gram_set, encoded_attr_name_str

# -----------------------------------------------------------------------------

def gen_bloom_filter_dict(attr_val_q_gram_dict, hash_type, bf_len,
                          num_hash_funct):
  """Encode the q-gram sets in the given dictionary into Bloom filters of the
     given length using the given number of hash functions.

     Return a dictionary with keys being q-gram sets (as tuples) and values
     being Bloom filters (bit arrays), a dictionary of bit positions (keys)
     and which q-grams were hashed to then (values), and a dictionary of atom
     BFs which encode a single q-gram (one such BF for each unique q-gram).
  """

  start_time = time.time()

  print 'Generate Bloom filter bit-patterns for %d q-gram sets' % \
        (len(attr_val_q_gram_dict))
  print '  Bloom filter length:          ', bf_len
  print '  Number of hash functions used:', num_hash_funct
  print '  Hashing type used:            ', \
        {'dh':'Double hashing', 'rh':'Random hashing'}[hash_type]
  print

  bf_dict = {}  # One BF per q-gram set

  bit_pos_q_gram_dict = {}  # Bit pos. are keys, q-grams hashed to them values

  atom_bf_dict = {}  # Keys are q-grams, values their atom BF
  
  num_q_gram_set = 0  # Count how many q-gram sets processed

  bf_len_m1 = bf_len-1

  for (attr_val, q_gram_set) in attr_val_q_gram_dict.iteritems():
    num_q_gram_set += 1

    if (num_q_gram_set % 10000 == 0):
      time_used = time.time() - start_time
      print '  Generated %d Bloom filters in %d sec (%.3f msec average)' % \
            (num_q_gram_set, time_used, 1000.0*time_used/num_q_gram_set)

    rec_bf = bitarray.bitarray(bf_len)
    rec_bf.setall(0)

    for q_gram in q_gram_set:  # Hash all q-grams into bits in the BF

      if (q_gram not in atom_bf_dict):  # We need to generate the atom BF
        atom_bf = bitarray.bitarray(bf_len)
        atom_bf.setall(0)

      if (hash_type == 'dh'):  # Double hashing
        hex_str1 = BF_HASH_FUNCT1(q_gram).hexdigest()
        int1 =     int(hex_str1, 16)
        hex_str2 = BF_HASH_FUNCT2(q_gram).hexdigest()
        int2 =     int(hex_str2, 16)

        for i in range(1,num_hash_funct+1):  # Ensure i is not 0
          pos = int((int1 + i*int2) % bf_len)
          rec_bf[pos] = 1

          if (q_gram not in atom_bf_dict):
            atom_bf[pos] = 1

          bit_pos_q_gram_set = bit_pos_q_gram_dict.get(pos, set())
          bit_pos_q_gram_set.add(q_gram)
          bit_pos_q_gram_dict[pos] = bit_pos_q_gram_set

      elif (hash_type == 'rh'):  # Random hashing
        random_seed = random.seed(q_gram)

        for i in range(num_hash_funct):
          pos = random.randint(0, bf_len_m1)
          rec_bf[pos] = 1

          if (q_gram not in atom_bf_dict):
            atom_bf[pos] = 1

          bit_pos_q_gram_set = bit_pos_q_gram_dict.get(pos, set())
          bit_pos_q_gram_set.add(q_gram)
          bit_pos_q_gram_dict[pos] = bit_pos_q_gram_set

      else:  # Should not happend
        raise Exception, hash_type

      if (q_gram not in atom_bf_dict):
        atom_bf_dict[q_gram] = atom_bf

    bf_dict[attr_val] = rec_bf

  print

  num_q_gram_at_pos_list = []  # To calculate statistics

  for pos in sorted(bit_pos_q_gram_dict.keys()):
    num_q_gram_at_pos_list.append(len(bit_pos_q_gram_dict[pos]))

  print '  Number of q-grams assigned to bit positions:'
  print '    Minimum: %d' % (min(num_q_gram_at_pos_list))
  print '    Average: %.1f' % (numpy.mean(num_q_gram_at_pos_list))
  print '    Median:  %d' % (numpy.median(num_q_gram_at_pos_list))
  print '    Maximum: %d' % (max(num_q_gram_at_pos_list))
  print '  Generated atom BFs for %d q-grams' % (len(atom_bf_dict))
  print

  assert len(bf_dict) == len(attr_val_q_gram_dict)

  return bf_dict, bit_pos_q_gram_dict, atom_bf_dict

# -----------------------------------------------------------------------------

def get_bf_segments(bf_dict, bf_seg_len):
  """From the given Bloom filter dictionary, extract for each BF the segment
     of the required length.

     Return a new dictionary with the same keys and values being the BF
     segments.
  """

  bf_seg_dict = {}

  for (key_val, bf) in bf_dict.iteritems():
    bf_seg_dict[key_val] = bf[:bf_seg_len]
    assert len(bf_seg_dict[key_val]) == bf_seg_len

  print 'Extracted BF segments of length %d bits from %d BFs' % \
        (bf_seg_len, len(bf_seg_dict))
  print

  return bf_seg_dict

# -----------------------------------------------------------------------------

def bf_segment_get_num_q_gram(bit_pos_q_gram_dict, bf_seg_len, num_hash_funct):
  """Get the number of unique q-grams that have been hashed into at least one
     bit position in the given BF segment. For each of these q-grams count in
     how many bit positions the q-gram is encoded.

     Returns the number of q-grams hashed into bits in the segment, the
     minimum, average, median, and maximum number of times a q-gram is hashed
     into a bit in the segment.
  """

  print 'Get the number of unique q-grams that have been hashed into at ' + \
        'least one bit position in the given BF segment.'
  print '  Length of BF segment:', bf_seg_len


  seg_q_gram_count_dict = {}  # Number of positions each q-gram is encoded into
  all_q_gram_count_dict = {}  # Should be number of hash functions for this

  for (pos, pos_q_gram_set) in bit_pos_q_gram_dict.iteritems():
    for q_gram in pos_q_gram_set:
      all_q_gram_count_dict[q_gram] = all_q_gram_count_dict.get(q_gram,0) + 1
      if (pos < bf_seg_len):
        seg_q_gram_count_dict[q_gram] = seg_q_gram_count_dict.get(q_gram,0) + 1

  seg_q_gram_count_list = seg_q_gram_count_dict.values()
  all_q_gram_count_list = all_q_gram_count_dict.values()

  # Check for all that no count is larger than number of hash functions used
  #
  assert max(all_q_gram_count_list) <= num_hash_funct

  print '  There are %d unique q-grams encoded into bit positions in this ' \
        % (len(seg_q_gram_count_dict)) + 'segment, from a total of %d ' % \
          (len(all_q_gram_count_dict))+'q-grams encoded'
  print '    Number of positions each q-gram is hashed into in segment and ' + \
        'full BF:'
  print '      (note for the full BF this is likely less than the number of' + \
        ' hash functions (%d) due to collisions)' % (num_hash_funct)
  print '    Minimum: %d / %d' % (min(seg_q_gram_count_list),
                                  min(all_q_gram_count_list))
  print '    Average: %.1f / %.1f' % (numpy.mean(seg_q_gram_count_list),
                                      numpy.mean(all_q_gram_count_list))
  print '    Median:  %d / %d' % (numpy.median(seg_q_gram_count_list),
                                  numpy.median(all_q_gram_count_list))
  print '    Maximum: %d / %d' % (max(seg_q_gram_count_list),
                                  max(all_q_gram_count_list))
  print

  return len(seg_q_gram_count_dict), min(seg_q_gram_count_list), \
         numpy.mean(seg_q_gram_count_list), \
         numpy.median(seg_q_gram_count_list), max(seg_q_gram_count_list)

# -----------------------------------------------------------------------------

def bf_segment_atom_attack(ot_bf_seg_dict, my_atom_bf_seg_dict,
                           my_bit_pos_q_gram_dict, q_gram_attr_val_dict,
                           num_bf_to_attack):
  """Use atom BFs (for individual q-grams) to identify which q-grams can be
     encoded in a BF segment of the other DO. Then further filter possible
     q-grams by removing those known to be hashed to a bit position where a
     BF segment has a 0-bit (these could be false positive atoms due to
     collisions). Finally for each BF segment find the attribute value(s)
     that contain(s) the largest number of the identified q-grams.

     Returns the number of correct 1-1, correct 1-many, wrong, and no matches
     where the sum of these numbers will be equal to 'num_bf_to_attack' (or
     equal to all BFs in the given BF dictionary if 'num_bf_to_attack' is
     given as 'all')
  """

  start_time = time.time()

  ot_num_bf_seg = len(ot_bf_seg_dict)

  if (num_bf_to_attack == 'all'):
    ot_num_bf_to_attack = ot_num_bf_seg
  else:
    assert num_bf_to_attack <= ot_num_bf_seg
    ot_num_bf_to_attack = num_bf_to_attack

  ot_attr_val_to_attack_list = random.sample(ot_bf_seg_dict.keys(),
                                             ot_num_bf_to_attack)

  print 'Attack BF segments by atom BF matching BF segment bit patterns'
  print '  Number of other DO BF segments:   ', ot_num_bf_seg
  print '    Number of BF segments to attack:', ot_num_bf_to_attack
  print '  Number of atom BFs:               ', len(my_atom_bf_seg_dict)
  print

  num_bf = 0  # Count how many BFs processed

  num_corr_1_1_attr_matches = 0  # Counts of how good the attack is
  num_corr_1_m_attr_matches = 0
  num_wrong_1_matches =       0
  num_wrong_m_matches =       0
  num_no_matches =            0

  # How many more q-grams identified versus how many are encoded
  #
  diff_true_poss_size = []

  # For the second (filtering) step, count total reduction in possible q-grams
  #
  zero_bit_num_q_gram_removed = 0

  # Loop over all other BF segments and find the possible q-grams that could
  # have been encoded into a segment
  #
  for ot_attr_val in ot_attr_val_to_attack_list:
    ot_bf_seg = ot_bf_seg_dict[ot_attr_val]
    ot_true_q_gram_set = ot_attr_val_q_gram_dict[ot_attr_val] # True q-gram set

    num_bf += 1

    if (num_bf % 10000 == 0):
      time_used = time.time() - start_time
      print '  Analysed %d Bloom filters in %d sec (%.3f msec average)' % \
            (num_bf, time_used, 1000.0*time_used/num_bf)

    poss_q_gram_set = set()  # The q-grams possibly encoded in the BF segment

    # Step 1: The set of possibly encoded q-grams based on atoms that have all
    # their 1-bits set in the BF segment
    #
    for (atom_q_gram, atom_bf_seg) in my_atom_bf_seg_dict.iteritems():
      if (atom_bf_seg & ot_bf_seg == atom_bf_seg):
        poss_q_gram_set.add(atom_q_gram)

    # Step 2: For 0-bits in the BF segment, remove from the set of possible
    # q-grams those that we know have been hashed to that position (these
    # possible q-grams could have been identified as atoms due to collisions)
    #
    for (pos, bit) in enumerate(ot_bf_seg):
      if (bit == False):  # A 0-bit

        # Get the q-grams we know have been hashed to this position
        #
        my_pos_q_gram_set = my_bit_pos_q_gram_dict[pos]

        # Remove them from the set of possible q-grams
        #
        for q_gram in my_pos_q_gram_set:
          if (q_gram in poss_q_gram_set):
            poss_q_gram_set.remove(q_gram)
            zero_bit_num_q_gram_removed += 1
            print 'removed', q_gram

    # Step 3: Get possible attribute values that contain one or more of the
    # possible q-grams, and select the attribute value with the largest number
    # of such q-grams to be the most likely value encoded in this BF
    #
    attr_val_accu = {}  # Keys will be attribute values, values counts of how
                        # many q-grams they have in the set of possible q-grams

    # TODO: this below process could be rather slow... need to improve *******

    max_count = -1

    for q_gram in poss_q_gram_set:
      q_gram_attr_val_set = q_gram_attr_val_dict[q_gram]
      for attr_val in q_gram_attr_val_set:
        count = attr_val_accu.get(attr_val, 0) + 1
        attr_val_accu[attr_val] = count
        max_count = max(count, max_count)

    found_attr_val_list = []

    # Find those attribute value(s) that have the maximum count (as how many
    # q-grams they have in the set of possible q-grams)
    #
    for (attr_val, count) in attr_val_accu.iteritems():
      if (count == max_count):
        found_attr_val_list.append(attr_val)

#    print '  Most likely encoded attribute values(s):', found_attr_val_list
#    print '    True encoded attribute values:', ot_attr_val

    # Check if the found value(s) are correct:
    #
    if (len(found_attr_val_list) == 0):
      num_no_matches += 1
    elif (ot_attr_val in found_attr_val_list):
      if (len(found_attr_val_list) == 1):
        num_corr_1_1_attr_matches += 1
      else:
        num_corr_1_m_attr_matches += 1
    else:
      if (len(found_attr_val_list) == 1):
        num_wrong_1_matches += 1
      else:
        num_wrong_m_matches += 1
  print

  print '  Filtering step using 0-bits removed a total %d q-grams' % \
        (zero_bit_num_q_gram_removed) + ' from sets of possible q-grams'
  print

  print '  Number of correct attribute values identified 1-to-1:    ' + \
        '%d (%.2f%%)' % (num_corr_1_1_attr_matches, 100.0 * \
                         num_corr_1_1_attr_matches/ot_num_bf_to_attack)
  print '  Number of correct attribute values identified 1-to-many: ' + \
        '%d (%.2f%%)' % (num_corr_1_m_attr_matches, 100.0 * \
                         num_corr_1_m_attr_matches/ot_num_bf_to_attack)
  print '  Number of wrong 1-to-1 attribute values identified:      ' + \
        '%d (%.2f%%)' % (num_wrong_1_matches, 100.0 * \
                         num_wrong_1_matches/ot_num_bf_to_attack)
  print '  Number of wrong 1-to-many attribute values identified:   ' + \
        '%d (%.2f%%)' % (num_wrong_m_matches, 100.0 * \
                         num_wrong_m_matches/ot_num_bf_to_attack)
  print '  Number of no attribute values identified:                ' + \
        '%d (%.2f%%)' % (num_no_matches, 100.0 * \
                         num_no_matches/ot_num_bf_to_attack)
  print

  assert (num_corr_1_1_attr_matches + num_corr_1_m_attr_matches + \
         num_wrong_1_matches + num_wrong_m_matches + num_no_matches) == \
         ot_num_bf_to_attack

  return (num_corr_1_1_attr_matches, num_corr_1_m_attr_matches, \
          num_wrong_1_matches, num_wrong_m_matches, num_no_matches)

# =============================================================================
# Main program

main_start_time = time.time()

command_line_call = sys.argv

q =                int(sys.argv[1])
hash_type =        sys.argv[2].lower()
num_hash_funct =   sys.argv[3]
bf_len =           int(sys.argv[4])
#
my_data_set_name = sys.argv[5]
ot_data_set_name = sys.argv[6]
rec_id_col =       int(sys.argv[7])
col_sep_char =     sys.argv[8]
header_line_flag = eval(sys.argv[9])
attr_list =        eval(sys.argv[10])
bf_seg_perc_list = eval(sys.argv[11])
num_bf_to_attack = sys.argv[12]

assert q >= 1, q
assert hash_type in ['dh','rh'], hash_type
if num_hash_funct.isdigit():
  num_hash_funct = int(num_hash_funct)
  assert num_hash_funct >= 1, num_hash_funct
else:
  assert num_hash_funct in ['opt', 'opt_half', 'opt_quarter'], num_hash_funct
assert bf_len > 1, bf_len
#
assert rec_id_col >= 0, rec_id_col
assert header_line_flag in [True,False], header_line_flag
assert isinstance(attr_list, list), attr_list
assert isinstance(bf_seg_perc_list, list), bf_seg_perc_list
if (num_bf_to_attack != 'all'):
  num_bf_to_attack = int(num_bf_to_attack)
  assert num_bf_to_attack > 1, num_bf_to_attack

my_base_data_set_name = my_data_set_name.split('/')[-1].replace('.csv', '')
my_base_data_set_name = my_base_data_set_name.replace('.gz','')
ot_base_data_set_name = ot_data_set_name.split('/')[-1].replace('.csv', '')
ot_base_data_set_name = ot_base_data_set_name.replace('.gz','')

assert ',' not in my_base_data_set_name
assert ',' not in ot_base_data_set_name

print
print '-'*80
print

# -----------------------------------------------------------------------------
# Step 1: Load the data sets and extract q-grams for selected attributes
#
my_attr_val_q_gram_dict, my_q_gram_attr_val_dict, my_avr_num_q_gram, \
   my_all_q_gram_set, my_encoded_attr_name_str = \
                       load_data_set_extract_q_grams(my_data_set_name,
                                                     rec_id_col, attr_list,
                                                     col_sep_char,
                                                     header_line_flag, q)

ot_attr_val_q_gram_dict, ot_q_gram_attr_val_dict, ot_avr_num_q_gram, \
   ot_all_q_gram_set, ot_encoded_attr_name_str = \
                       load_data_set_extract_q_grams(ot_data_set_name,
                                                     rec_id_col, attr_list,
                                                     col_sep_char,
                                                     header_line_flag, q)

assert my_encoded_attr_name_str == ot_encoded_attr_name_str

# Generate a dictionary with all q-grams and their attribute values from both
# data sets
#
my_num_q_gram = len(my_q_gram_attr_val_dict)
ot_num_q_gram = len(ot_q_gram_attr_val_dict)

all_q_gram_attr_val_dict =    {}

for (q_gram, attr_val_set) in my_q_gram_attr_val_dict.iteritems():
  all_q_gram_attr_val_dict[q_gram] = attr_val_set
for (q_gram, attr_val_set) in ot_q_gram_attr_val_dict.iteritems():
  q_gram_attr_val_set = all_q_gram_attr_val_dict.get(q_gram, set())
  q_gram_attr_val_set = q_gram_attr_val_set | attr_val_set
  all_q_gram_attr_val_dict[q_gram] = q_gram_attr_val_set

num_all_q_gram =    len(all_q_gram_attr_val_dict)
num_common_q_gram = len(set(my_q_gram_attr_val_dict.keys()) & \
                        set(ot_q_gram_attr_val_dict.keys()))

print 'A total of %d unique q-grams occur in both data set' % (num_all_q_gram)
print '  Of these, %d occur in both data sets' % (num_common_q_gram)
print

num_common_attr_val = len(set(my_attr_val_q_gram_dict.keys()) & \
                          set(ot_attr_val_q_gram_dict.keys()))
num_my_attr_val = len(my_attr_val_q_gram_dict)
num_ot_attr_val = len(ot_attr_val_q_gram_dict)

jacc_common_attr_val = float(num_common_attr_val) / \
  (num_my_attr_val + num_ot_attr_val - num_common_attr_val)

print 'My database contains %d unique attribute values' % (num_my_attr_val)
print 'The other database contains %d unique attribute values' % \
      (num_ot_attr_val)
print '  Number of unique attribute values in common: %d' % \
      (num_common_attr_val)
print '    Jaccard based overlap of common attribute values: %.1f%%' % \
      (100.0*jacc_common_attr_val)
print

# -----------------------------------------------------------------------------
# Step 2: Generate Bloom filters from q-gram sets
#
if (num_hash_funct in ['opt', 'opt_half', 'opt_quarter']):

  # Set number of hash functions to have in average 50% of bits set to 1
  # (Linking Sensitive Data book, 2020)
  # num_hash_funct = int(math.ceil(0.5 * BF_LEN / \
  #                                math.floor(avrg_num_q_gram)))
  #
  opt_num_hash_funct = int(round(numpy.log(2.0) * float(bf_len) / \
                                 my_avr_num_q_gram))
  if (num_hash_funct == 'opt'):
    num_hash_funct = opt_num_hash_funct
  elif (num_hash_funct == 'opt_half'):
    num_hash_funct = int(round(opt_num_hash_funct / 2.0))
  elif (num_hash_funct == 'opt_quarter'):
    num_hash_funct = int(round(opt_num_hash_funct / 4.0))
  else:
    raise Exception, num_hash_funct

my_bf_dict, my_bit_pos_q_gram_dict, my_atom_bf_dict = \
    gen_bloom_filter_dict(my_attr_val_q_gram_dict, hash_type, bf_len,
                          num_hash_funct)

ot_bf_dict, ot_bit_pos_q_gram_dict, ot_atom_bf_dict = \
    gen_bloom_filter_dict(ot_attr_val_q_gram_dict, hash_type, bf_len,
                          num_hash_funct)

# Header string for results output
#
print '### command_line_call, encoded_attr_name_str, num_hash_funct, ' + \
      'num_my_attr_val, num_ot_attr_val, num_common_attr_val, ' + \
      'jacc_common_perc, my_num_q_gram, ot_num_q_gram, num_all_q_gram, ' + \
      'num_common_q_gram, bf_seg_len, bf_seg_perc, my_num_q_gram_bf_seg, ' + \
      'my_min_num_bit_pos, my_avr_num_bit_pos, my_med_num_bit_pos, ' + \
      'my_max_num_bit_pos, ot_num_q_gram_bf_seg, ot_min_num_bit_pos, ' + \
      'ot_avr_num_bit_pos, ot_med_num_bit_pos, ot_max_num_bit_pos, ' + \
      'atom_num_corr_1_1_attr_matches, atom_num_corr_1_m_attr_matches, ' + \
      'atom_num_wrong_1_matches,atom_num_wrong_m_matches, atom_num_no_matches'

# -----------------------------------------------------------------------------
# Step 3: Run the segment attack with different segment percentages
#
for bf_seg_perc in bf_seg_perc_list:

  print '-'*80
  print

  # Generate a string to be printed as the result summary
  #
  res_str = '### "' + ' '.join(command_line_call)
  res_str = res_str.replace(' , ', ' comma ')  # The separator in input file
  res_str = res_str.replace(',', ';') + '", '

  # Details of how many attribute values in the two data sets, and how many
  # occur in common in both data sets
  #
  res_str += '%s, %d, %d, %d, %d, %.1f, ' % (my_encoded_attr_name_str,
                                             num_hash_funct, num_my_attr_val,
                                             num_ot_attr_val,
                                             num_common_attr_val,
                                             100.0*jacc_common_attr_val)

  # Details of how many q-grams in the two data sets, how many in total,
  # and how many occur occur in common in both data sets
  #
  res_str += '%d, %d, %d, %d, ' % (my_num_q_gram, ot_num_q_gram, \
                                   num_all_q_gram, num_common_q_gram)

  bf_seg_len = int(float(bf_len)*bf_seg_perc/100)

  # Get the BF segments from the BFs of both data sets
  #
  my_bf_seg_dict = get_bf_segments(my_bf_dict, bf_seg_len)
  ot_bf_seg_dict = get_bf_segments(ot_bf_dict, bf_seg_len)

  my_atom_bf_seg_dict = get_bf_segments(my_atom_bf_dict, bf_seg_len)
  my_num_q_gram_bf_seg, my_min_num_bit_pos, my_avr_num_bit_pos, \
         my_med_num_bit_pos, my_max_num_bit_pos = \
                  bf_segment_get_num_q_gram(my_bit_pos_q_gram_dict,
                                            bf_seg_len, num_hash_funct)
  ot_num_q_gram_bf_seg, ot_min_num_bit_pos, ot_avr_num_bit_pos, \
         ot_med_num_bit_pos, ot_max_num_bit_pos = \
                  bf_segment_get_num_q_gram(ot_bit_pos_q_gram_dict,
                                            bf_seg_len, num_hash_funct)

  # Add BF segment information to result string
  #
  res_str += '%d, %d%%, %d, %d, %.2f, %d, %d, ' % (bf_seg_len, bf_seg_perc, \
                                                 my_num_q_gram_bf_seg, \
                                                 my_min_num_bit_pos, \
                                                 my_avr_num_bit_pos, \
                                                 my_med_num_bit_pos, \
                                                 my_max_num_bit_pos)
  res_str += '%d, %d, %.2f, %d, %d, ' % (ot_num_q_gram_bf_seg, \
                                       ot_min_num_bit_pos, \
                                       ot_avr_num_bit_pos, \
                                       ot_med_num_bit_pos, \
                                       ot_max_num_bit_pos)

  # Atom based attack
  #
  num_corr_1_1_attr_matches, num_corr_1_m_attr_matches, \
      num_wrong_1_matches, num_wrong_m_matches, \
      num_no_matches = bf_segment_atom_attack(ot_bf_seg_dict,
                                              my_atom_bf_seg_dict,
                                              my_bit_pos_q_gram_dict,
                                              all_q_gram_attr_val_dict,
                                              num_bf_to_attack)

  res_str += '%d, %d, %d, %d, %d' % (num_corr_1_1_attr_matches, \
                                     num_corr_1_m_attr_matches, \
                                     num_wrong_1_matches, num_wrong_m_matches, \
                                     num_no_matches)

  # Print result line for CSV generation
  #
  print res_str

# -----------------------------------------------------------------------------
# End.
