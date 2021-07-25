A Critique and Attack on “Blockchain-based Privacy-Preserving Record Linkage Enhancing Data Privacy in an Untrusted Environment"
================================================================================================================================

This archive contains code and data sets to run the atom Bloom filter based attack described in:

"A Critique and Attack on “Blockchain-based Privacy-Preserving Record Linkage Enhancing Data
Privacy in an Untrusted Environment”

The attack illustrates the privacy flaws of the blockchain based privacy-preserving record linkage
protocol proposed by Nobrega et al. (Information Systems, 2021).

See the beginning of the Python module "bf-segment-attack.py" for information about how to run
the attack, and the run-all.sh shell script to run a large set of experiments, where summary
results are output in lines starting with '###'.

Requirements
============

Written in in Python 2.7, and requiring the libraries 'bitarray' and 'numpy'.

The run script generates output that can be converted into a CSV file using

grep \#\#\# results-text-file.txt > results-file.csv

See the file  "bf-segment-atom-attack-results.csv" for a set of such results.

Authors
=======

Peter Christen [a,b], Rainer Schnell [c], Thilina Ranbaduge [a,d], and Anushka Vidanage [a]

  a School of Computing, The Australian National University, Canberra, Australia
  
  b University of Leipzig and ScaDS.AI, Leipzig, Germany
  
  c University of Duisburg-Essen, Duisburg, Germany
  
  d Data61, Black Mountain, Canberra, Australia

Contact: peter.christen@anu.edu.au
