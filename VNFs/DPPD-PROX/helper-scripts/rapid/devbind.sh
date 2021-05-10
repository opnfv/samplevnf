link="$(sudo ip -o link | grep MACADDRESS |cut -d":" -f 2)"
if [ -n "$link" ];
then
       echo Need to bind
       # Uncomment one of the following lines, depending on which driver
       # you want to use: vfio-pci or igb_uio
       #sudo /opt/rapid/dpdk/usertools/dpdk-devbind.py --force --bind igb_uio $(sudo /opt/rapid/dpdk/usertools/dpdk-devbind.py --status |grep  $link | cut -d" " -f 1)
       sudo driverctl set-override $(sudo ethtool -i $link |grep bus-info | cut -d" " -f 2) vfio-pci
else
       echo Assuming port is already bound to DPDK poll mode driver
fi
exit 0
