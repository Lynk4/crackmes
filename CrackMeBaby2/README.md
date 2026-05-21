# CanYouCrackMeBaby2 - Writeup

Crackme: [https://crackmes.one/crackme/6a0bd0592b3df128c1df5c16](https://crackmes.one/crackme/6a0bd0592b3df128c1df5c16) 

[https://crackmes.one/crackme/6a0bd0592b3df128c1df5c16](https://crackmes.one/crackme/6a0bd0592b3df128c1df5c16)

**Binary**: CanYouCrackMeBaby2.exe

**Arch**: x86-64 PE (Windows)

**Tools**: IDA Pro

**Author**: Igr0t7

---

## **Anti-Debug**

The binary checks for running debuggers using `CreateToolhelp32Snapshot` + `Process32First/Next`. It looks for process names like `x64dbg.exe`, `ida.exe`, `ollydbg.exe`, etc. If found, it shows a message box and exits.

**Bypass**: Patch the conditional jump after the anti-debug call from `jz` to `jmp`, or just analyze statically.

---

## **Finding main**

Open the Strings window (`Shift+F12`), find `"Input the pass:"`, press `X` for xrefs — this takes us to `main`.

---

## **The Trap (Fake Flag)**

In `main`, the first check compares our input directly to a hardcoded string:

```
c

if(len==20&&!memcmp(input,"flag{can-you-crack?}",20))
```

This looks like the answer, but it's a **decoy** — entering it prints `"Access Denied"`.

---

## **The Real Check**

If the first check fails, the program **XORs our input with `0x0A`** and compares it to a ciphertext:

```
c

for(i=0; i< len; i++)
    input[i]^=0x0A;
if(len==18&&!memcmp(xored_input,"lfkm0cmx:~'~boacdm",18))
```

The XOR key `0x0A` (10 decimal) is hardcoded as an immediate value in the instruction:

```
asm

140001e40  xor     byte ptr [rax+rcx], 0Ah
```

In the decompiler (F5) it appears as:

```
c

*((_BYTE*)v9+ v7++)^=0xAu;
```

To get the password, we reverse the XOR:

```
python

>>>''.join(chr(ord(c)^0x0A)for cin"lfkm0cmx:~'~boacdm")
'flag:igr0t-theking'
```

**Password**: `flag:igr0t-theking`

---

## **Stage 2**

After entering the correct password, it asks `"Say my name..."` and compares our input to:

```
c

if(len==5&&!memcmp(input2,"igr0t",5))
print("You Win.. (;");
```

**Answer**: `igr0t`

---

## **Solution**

```

Input the pass:
flag:igr0t-theking
You are good , but...
Say my name...
igr0t
You Win.. (;
```

![Screenshot 2026-05-21 at 5.42.25 PM.png](CanYouCrackMeBaby2%20-%20Writeup/Screenshot_2026-05-21_at_5.42.25_PM.png)

---