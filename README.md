

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

## Tag SSD’s When Using vSAN OSA

This is ONLY for ESX hosts with SSD’s of the same capacity/speed when using vSAN OSA. 

Problem: 
OSA needs SSD's marked as capacity, and at least 1 SSD for cache. It can't have unused SSD's available besides cache disks(s). See KB https://knowledge.broadcom.com/external/article/410836/vsan-osa-create-vsan-disk-groups-failur.html 

Goal:  
Keep 4 SSD's marked as capacity disks, 1 SSD for cache, 1 SSD used for boot OS. Take the remaining and set as vSAN Direct to make them ineligible for vSAN. 

Process: 

We’ll create files to track which SSD device ID’s will be used: 
* `device-id-all.txt` – Contains all SSD device ID’s. 
* `device-id-vsan-direct.txt` – Contains unused SSD’s. 
* `device-id-vsan-capacity.txt` – Contains SSD’s to be used as capacity tier. 
Enable SSH on each host and ssh to the hosts. 

### Manual method 
Create text file containing all device id's:  
`esxcli storage core device list |grep -i ^naa. >device-id-all.txt`

Make a copy of the file:  
`cp device-id-all.txt device-id-vsan-direct.txt`

Copy 4 device ID's from `device-id-vsan-direct.txt` to `device-id-vsan-use.txt`.  
Remove them from `device-id-vsan-direct.txt` 
From `device-id-vsan-direct.txt` remove the device-id used for boot disk. (Check the UI or `esxcli storage core device list |grep -B 30 "Is Boot Device: true"`.) 
From `device-id-vsan-direct.txt` remove another device id to be used as cache disk.  
Mark remaining device id's as vSAN Direct so they won't be used for vSAN cache. 
```
while read -r dev; do 
    [ -n "$dev" ] && esxcli vsan storage tag add -d "$dev" -t vsanDirect  
done < device-id-vsan-direct.txt  
```

Mark SSD's as capacity for use in vSAN. 
```
while read -r dev; do 
    [ -n "$dev" ] && esxcli vsan storage tag add -d "$dev" -t capacityFlash  
done < device-id-vsan-capacity.txt  
```
### Scripted method 
Paste the following into the ESX shell:
```
esxcli storage core device list |grep -i ^naa. >device-id-all.txt 
cp device-id-all.txt device-id-vsan-direct.txt 

tail -n 4 device-id-vsan-direct.txt >device-id-vsan-capacity.txt 
grep -Fvx -f device-id-vsan-capacity.txt device-id-vsan-direct.txt > device-id-vsan-direct.txt.new && mv -f device-id-vsan-direct.txt.new device-id-vsan-direct.txt 
esxcli storage core device list |grep -B 30 "Is Boot Device: true" | sed -n '2p' > device-id-boot.txt 
grep -Fvx -f device-id-boot.txt device-id-vsan-direct.txt > device-id-vsan-direct.txt.new && mv -f device-id-vsan-direct.txt.new device-id-vsan-direct.txt 
sed -i '$d' device-id-vsan-direct.txt 

while read -r dev; do 
    [ -n "$dev" ] && esxcli vsan storage tag add -d "$dev" -t vsanDirect  
done < device-id-vsan-direct.txt  

while read -r dev; do 
    [ -n "$dev" ] && esxcli vsan storage tag add -d "$dev" -t capacityFlash  
done < device-id-vsan-capacity.txt  
```
### Verification 

From 24 disks: 4 tagged as capacity. 18 tagged as vSAN Direct. 1 default as cache. 1 as OS boot.  

Count disks tagged at capacity: `vdq -q |grep -iB8 -A5 "\"IsCapacityFlash\":  \"1\"" |grep -i naa. |wc -l `

Count disks tagged as vSAN Direct: `vdq -q |grep -iB12 -A1 "\"IsVsanDirectDisk\":  \"1\"" |grep -i naa. |wc -l` 
