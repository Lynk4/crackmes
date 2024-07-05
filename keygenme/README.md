---

<img width="904" alt="Screenshot 2024-07-06 at 4 07 18 AM" src="https://github.com/Lynk4/crackmes/assets/44930131/899a451a-7aa7-4843-9c18-949a4e71fe2a">

[Access this challenge](https://crackmes.one/crackme/5d24585133c5d410dc4d0cbd)

---
**Password for the zip file is ```crackmes.one```**

---

now let's analyze the executable binary in ghidra:.........

---
Renaming some functions.......

here is the result........


<img width="1353" alt="Screenshot 2024-07-06 at 3 45 46 AM" src="https://github.com/Lynk4/crackmes/assets/44930131/a8f92031-8e29-4bd7-a90c-b868ec6c7449">


so the algorith is this

if ((sum ^ first_char_name * 3) << ((byte)program_name_length & 0x1f) == key_as_int) {

---

let's test our hypothesis .........

---
```python
❯ python3
Python 3.11.8 (main, Feb  7 2024, 21:52:08) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> ord("a")
97
>>> 97 ^ 97 * 3
322
>>> 322 << len("./keygenme")&0x1f
0
>>> 322 << (len("./keygenme")&0x1f)
329728
>>> exit()
❯ ./keygenme a 329728
Good job!
```

---

oh yeah!!!!!!!!!! it's working..............

let's make key generator in python..........

---
```python
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
```

let's run it..........

```bash
❯ python3 keygen.py lynk ./keygenme
256000
❯ ./keygenme lynk 256000
Good job!
```

---
It's working................................................
