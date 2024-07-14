# crackc_by_pride

---


<img width="902" alt="Screenshot 2024-07-14 at 6 35 52 AM" src="https://github.com/user-attachments/assets/c1c78dc7-be65-49c4-a967-36d7f970dac6">


[Challenge](https://crackmes.one/crackme/5ab77f5933c5d40ad448c457)

---

It's a 32 bit binary..

let's run it.

<img width="497" alt="1" src="https://github.com/user-attachments/assets/1fd3613f-c135-4c7f-a248-ebea55705031">

so the binary asks for a name and a serial key..

open the binary in x32dbg. and right click > search for > itermodular calls > all modules.

<img width="1269" alt="2" src="https://github.com/user-attachments/assets/532e08fd-3190-464e-a80d-c56185a19e27">

then search for msvcrt.system and click on it........

<img width="1270" alt="3" src="https://github.com/user-attachments/assets/7174d63b-10a4-45ee-830a-66f6de084032">

<img width="1270" alt="4" src="https://github.com/user-attachments/assets/897a0397-35ab-485c-8884-fc164d23f08b">

Now set a brak point.

<img width="1267" alt="5" src="https://github.com/user-attachments/assets/9ad6aa85-b95d-4f94-914b-4a9e0dbb1d99">


set another break point before comparison...
 
<img width="1267" alt="6" src="https://github.com/user-attachments/assets/a7080491-e96f-4ee8-bb07-03f6f852570d">

Check the value of eax register.

<img width="1270" alt="7" src="https://github.com/user-attachments/assets/d4b553f0-6d01-42ee-8e7d-a888b5ba9013">

enter the serial key...

<img width="1271" alt="8" src="https://github.com/user-attachments/assets/4dcafc49-4ae4-48e2-b2fe-aaf7e04fdcc4">


---

So the program takes a name as a input then it stores the lenght of the name.......

after that it adds 0xCA to lenth of the name

then a xor operaton 

length of name ^ 0x3D8D40F

---

python keygen..........

```python
name = input("Enter you name :")
length = len(name)
length += 0xCA
serial_key = length ^ 0x3D8D40F
print(f'serial key is :{serial_key}')
```

