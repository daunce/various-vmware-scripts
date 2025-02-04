

## Searching through logs

Searches recursively, case insenitive.
```
grep --include=\*.log -Rni . -e "<search term>"

-R recursive, including symbolic links
-n shows filename and line number
-i case insensitive
```

## SSH to ESXi host and regenerate certificates
Regenerates certificates, restarts services, and prints files to show timestamps and prove they've been updated.
```
ssh root@x.x.x.x "/sbin/generate-certificates; /etc/init.d/hostd restart && /etc/init.d/vpxa restart && /etc/init.d/rhttpproxy restart; date; ls -la /etc/vmware/ssl/rui*"
```
