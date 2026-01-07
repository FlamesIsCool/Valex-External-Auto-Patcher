# Valex External Auto Patcher

This is a simple tool I made in C++ that automatically patches `Valex_External.exe` so you don’t need to deal with the key system anymore.

It finds the EXE in your Downloads folder, scans the binary, and changes the right parts to bypass the auth check.

---

## 🛠️ What it does

- Looks for `Valex_External.exe` in:


```C:\Users\yournameok\Downloads\Valex_External\```


- Scans the file for these messages:

```
"Authentication failed"
"Authentication successful."
```

- Finds the instructions that control the login check
- Patches the binary so it always passes
- Saves a new file:


```patched_Valex_External.exe```


- Then it auto-launches it.

---

## 📂 Output

The patched file will be saved next to the original:

```C:\Users\yournameok\Downloads\Valex_External\patched_Valex_External.exe```

---

## ✅ How to run

Just compile and run it:

```bash
g++ patcher.cpp -o patcher.exe
```

Or use Visual Studio and build it like a normal C++ project.

Then open roblox then open the valex external crack and enter any key its ok if it says incorrect key the gui will still load.

---

## 🧬 Key Patch Logic (Code)

Here’s the part of the code that actually patches the binary:

```cpp
// Redirects failed message to success
patch(failed_lea_va, [&](size_t off) {
    int64_t rel = file_to_va(success_pos[0]) - (failed_lea_va + 7);
    *(int32_t*)&buf[off + 3] = (int32_t)rel;
});

// Forces auth check to always pass
patch(jne_va, [&](size_t off) {
    buf[off + 2] = 0xE9; // change JNE to JMP
    *(int32_t*)&buf[off + 3] = jne_rel + 1;
});
```

---

## 🎥 Demo Video

See how it works in action on YouTube:

[![Watch the video](https://img.youtube.com/vi/4bnnLXYFZP0/hqdefault.jpg)](https://www.youtube.com/watch?v=4bnnLXYFZP0)

Click the image above or this link: [https://www.youtube.com/watch?v=4bnnLXYFZP0](https://www.youtube.com/watch?v=4bnnLXYFZP0)


---

## 📌 Notes

* Only works on **64-bit Valex External**
* Doesn’t touch memory — it patches the file itself
* Doesn’t use hardcoded offsets — it finds stuff dynamically
* For learning purposes only

---

## 🧠 Why I made this

I got tired of typing in keys and wanted to mess around with binary patching. Thought it’d be cool to automate it.

If you want to learn about how PE files work or how to patch stuff, feel free to check the code.

---

## ⚠️ Disclaimer

This is for **educational use only**.
Don’t use this to mess with other people’s software or break any rules.

Use it at your own risk.
