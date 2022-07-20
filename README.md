# ROPEmporium

Solutions and writeups for ROPEmporium.

Only doing x86 (32-, 64-bit) for now...

## Notes

### Pwntools templates

Pwntools allows us to create a template script using the following command:

```bash
$ pwn template ./executable > script_name.py
```

The code generated allows us to attach GDB debugger to our running executable, giving us insight into what's happening as the program runs. You can tell pwntools to launch GDB when the script is running by issuing the command below. The `'GDB'` is very important.

```bash
$ python3 ./script_name.py 'GDB'
```

To save a few characters when you type out this command, you can give the script executable permissions.

```bash
$ python3 ./script_name.py GDB # virgin
$ chmod +x ./script_name.py
$ ./script_name.py GDB # chad
```

### Code snippets

The snippets in the `README.md`s in each folder contain snippets that may not match the corresponding lines in each `win.py` script. This was done to ensure readability in the `README.md`s, where this is not a priority in the scripts I wrote.

### Context terminal

You may also see the following line near the top of each `win.py` script:

```python
context.terminal = ["/usr/bin/konsole", "-e", "sh", "-c"]
```

This is the command used by pwntools to launch a new terminal to run a command like `gdb`. Since I am using KDE Plasma as my desktop environment, I have to tell pwntools to launch a new terminal using KDE Plasma's default terminal, namely [Konsole](https://konsole.kde.org/). Hence, the provided command line argument list uses `"/usr/bin/konsole"`, the path to where Konsole is installed on my system.

If you are using Kali Linux, the default terminal program should be [xfce4-terminal](https://docs.xfce.org/apps/xfce4-terminal/start) (i think), so your `context.terminal` should look something like this instead:

```python
context.terminal = ["/usr/bin/xfce4-terminal", "-e"]
```
