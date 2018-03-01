#/bin/bash!

# Helps compare config changes using diff from a Palo Alto config change
# Created on 01 Mar 2018 by TomSqr94 - v1.0

# First we need to enter the two sides to compare
read -p "Enter the config prior to the change: " before
read -p "Enter the config after the change: " after

echo $before >> before.txt
echo $after >> after.txt

# Sort the input into new lines after every space detected
tr -s ' ' '\n' < before.txt > before2.txt
tr -s ' ' '\n' < after.txt > after2.txt

# Compare the files line by line with diff
diff before2.txt after2.txt

# Remove the files that were created
rm before.txt && rm before2.txt && rm after.txt && rm after2.txt
