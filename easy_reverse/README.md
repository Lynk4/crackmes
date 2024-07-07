---
# easy_reverse

---

<img width="916" alt="Screenshot 2024-07-08 at 1 08 05 AM" src="https://github.com/Lynk4/crackmes/assets/44930131/245c3907-299f-46b6-b9f2-18c5c6e4b421">



[Access the challenge](https://crackmes.one/crackme/5b8a37a433c5d45fc286ad83)

---

let's unzip the zip file password is **crackmes.one**

running the binary.........

basic file check:

```bash
❯ file rev50_linux64-bit
rev50_linux64-bit: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6db637ef1b479f1b821f45dfe2960e37880df4fe, not stripped
❯ checksec --file=rev50_linux64-bit
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   68 Symbols	  No	0		1		rev50_linux64-bit

❯ ./rev50_linux64-bit
USAGE: ./rev50_linux64-bit <password>
try again!
❯ ./rev50_linux64-bit dontknow
USAGE: ./rev50_linux64-bit <password>
try again!
╭─ ~/crackmes/easy_reverse
╰─❯
```
---

So the prgram asking for password.......

let's analyze it in ghidra.........


---
main function........

<img width="1405" alt="Screenshot 2024-07-08 at 1 13 33 AM" src="https://github.com/Lynk4/crackmes/assets/44930131/9b9e74e6-87a5-4ac2-90aa-57cfaf019cda">


right click on the function name and click edit function signature........

put down this signature

<img width="1255" alt="edit function sign" src="https://github.com/Lynk4/crackmes/assets/44930131/fca8e299-0f3a-4dd8-b1b1-758c93fd56fa">

---

Now the code is much clear.........

<img width="1256" alt="clear code" src="https://github.com/Lynk4/crackmes/assets/44930131/681a2638-8ed9-4e02-85bf-4eb3295fcfce">


---

main function
```c
int main(int argc,char **argv__)

{
  size_t sVar1;

  if (argc == 2) {
    sVar1 = strlen(argv__[1]);
    if (sVar1 == 10) {
      if (argv__[1][4] == '@') {
        puts("Nice Job!!");
        printf("flag{%s}\n",argv__[1]);
      }
      else {
        usage(*argv__);
      }
    }
    else {
      usage(*argv__);
    }
  }
  else {
    usage(*argv__);
  }
  return 0;
}
```

---

so we need 10 characters and @ at the fith place of the password strings.............

let's test it......

<img width="517" alt="Screenshot 2024-07-08 at 12 59 42 AM" src="https://github.com/Lynk4/crackmes/assets/44930131/f599ca42-73df-4608-bf6e-850da736196c">

oh yeah.............it worked.............
---



