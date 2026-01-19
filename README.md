#RunAsEx

Simple executable to run other executables with user/password interactive session without interactive credential prompt.

This tool was written to overcome the ‘double-hop’ problem in evil-winrm, i.e. the inability to have a complete session with cached credentials.
The alternative to this tool is to create a scheduled task with explicit credentials and start it. 

Compile:
```bash
x86_64-w64-mingw32-gcc -o runasex.exe runasex.c -ladvapi32
```

Run:
```bash
./runasex.exe $DOMAIN\$USER $PASSWORD shell.exe
```


<img width="907" height="280" alt="immagine" src="https://github.com/user-attachments/assets/9aa8b5ff-4783-4170-84f8-6582044c53b9" />

---

<img width="662" height="198" alt="immagine" src="https://github.com/user-attachments/assets/046cd7ec-f835-4ee5-b773-39e982e404eb" />

---

<img width="669" height="441" alt="immagine" src="https://github.com/user-attachments/assets/4ef825d6-3115-4f3f-a0e2-8162c0fedf93" />






