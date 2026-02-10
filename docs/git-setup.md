# Git Setup Tips

## Use commit template
```powershell
git config commit.template .gitmessage
```

## Optional: enforce LF in repo
On Windows:
```powershell
git config core.autocrlf true
```
Or for stricter control, add `.gitattributes` and set autocrlf=input.
