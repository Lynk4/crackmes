# first golang crackme

---

![Screenshot 2026-05-28 at 4.58.55 PM.png](first%20golang%20crackme/Screenshot_2026-05-28_at_4.58.55_PM.png)

---

Crackme: [https://crackmes.one/crackme/6a1608d1d7ff92e1214c01f5](https://crackmes.one/crackme/6a1608d1d7ff92e1214c01f5)

---

### Ghidra decompiled main

```cpp

void main.main(void)

{
  int unaff_R14;
  undefined *local_50;
  undefined **local_48;
  undefined *local_40;
  undefined **local_38;
  undefined *local_30;
  undefined8 *local_28;
  undefined *local_20;
  undefined **local_18;
  undefined8 *local_10;
  
  while (&stack0x00000000 <= *(undefined1 **)(unaff_R14 + 0x10)) {
    runtime.morestack_noctxt.abi0();
  }
  local_20 = &DAT_1400bc1a0;
  local_18 = &PTR_s_Enter_password:_expected_integer_1400e49d0;
  fmt.Fprint(&go:itab.*os.File,io.Writer,os.Stdout,&local_20,1,1);
  local_28 = (undefined8 *)runtime.newobject(&DAT_1400bc1a0);
  local_30 = &DAT_1400b8b80;
  local_10 = local_28;
  fmt.Fscanln(&go:itab.*os.File,io.Reader,os.Stdin,&local_30,1,1);
  if ((local_10[1] == 8) && (*(int *)*local_10 == 0x33323161626d6973)) {
    local_40 = &DAT_1400bc1a0;
    local_38 = &PTR_DAT_1400e49e0;
    fmt.Fprintln(&go:itab.*os.File,io.Writer,os.Stdout,&local_40,1,1);
  }
  else {
    local_50 = &DAT_1400bc1a0;
    local_48 = &PTR_DAT_1400e49f0;
    fmt.Fprintln(&go:itab.*os.File,io.Writer,os.Stdout,&local_50,1,1);
  }
  fmt.Fscanln(&go:itab.*os.File,io.Reader,os.Stdin,0,0,0);
  return;
}

```

**Deassemble and Decompile `main.main`:**

Disassembling

reveals the core comparison logic:

- It prompts the user for input using `fmt.Fscanln`.
- It checks if the length of the input string is **exactly 8** (`cmpq $8, 8(%rdx)`).
- It loads the 64-bit immediate constant `0x33323161626d6973` (`3689065339102783859`) into register `%r8` and compares it with your input using `cmpq %r8, (%rdx)`.
- When decoded in little-endian order, the byte value of `0x33323161626d6973` translates directly to the string:

![Screenshot 2026-05-28 at 4.54.42 PM.png](first%20golang%20crackme/Screenshot_2026-05-28_at_4.54.42_PM.png)

#### Cyber chef decoding

![Screenshot 2026-05-28 at 4.54.56 PM.png](first%20golang%20crackme/Screenshot_2026-05-28_at_4.54.56_PM.png)

```
text

simba123
```

#### Verifying the password:

![Screenshot 2026-05-28 at 4.58.16 PM.png](first%20golang%20crackme/Screenshot_2026-05-28_at_4.58.16_PM.png)

---