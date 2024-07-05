#!/usr/bin/python3

import sys

def gen(name, program):
	# (sum ^ (firstchar * 3)) << (program_name_len0x1f)
	key = 0
	for c in name:
		key += ord(c)
	key ^= (ord(name[0])*3)
	key = key << (len(program)&0x1f)
	return key



if __name__ == "__main__":
	if len(sys.argv) != 3:
		print("give name and program name")
		exit(0)
	print(gen(sys.argv[1], sys.argv[2]))

