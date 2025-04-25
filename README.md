# phb_pythonscripts.
Python scripts that I have written for myself and think others might enjoy.

I write Python scripts for myself and to help me do my job. Sometimes when I write one that doesn't have any IP and I 
think other people can use, I drop it here.

Here is a list of them with descriptions...

### better_tree.py 
*FYI: written and tested in a \*nix compatible OS. Tested in Windows and seems to work, but ... meh. You're on your own. For 
what its worth it uses basic Python3 stuff so you should be fine. It seems fine to me in my Win11 VMs.*

better_tree.py is a replacement for the "tree" command that you will find in your favorite OS. It does the basic 
functionality as the normal "tree" command, but with these extra features...

- Is multi-threaded. Meaning it can be crazy fast. The default thread count is 10, but you can modify that with the 
-workers parameter...
```
-w WORKERS, --workers WORKERS
           Number of worker threads for parallel scanning
           (default: 10)
```

- Has output to a file built in. Default is no file output. You have to provide a filename for the script to dump to a 
file. Without a filename specified the script will output its tree data to the console using `more` 
```
-o OUTPUT, --output OUTPUT
           Output file to save the tree structure
```

- Follow symlinks. If you are on an OS with symlinks then this will allow you to follow or ignore them. By default it 
ignores them.

```
-f, --follow-symlinks
                        Follow symbolic links (default: ignore them)
```

- "Show hidden directories" allows you to show or hide hidden directories.

```
-a, --all             Show hidden directories (default: hide them)
```

- The -s (Security Findings) switch will look for directories with scary names and add them to a separate list for you 
to review. The keyword list is in the file and can be modified as needed.

```
-a, --all             Show hidden directories (default: hide them)
```