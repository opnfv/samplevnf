link="$(sudo ip -o link | grep MACADDRESS |cut -d":" -f 2)"
if [ -n "$link" ];
then
       echo Need to bind
       sudo ~/dpdk/usertools/dpdk-devbind.py --force --bind igb_uio $(sudo ~/dpdk/usertools/dpdk-devbind.py --status |grep  $link | cut -d" " -f 1)
else
       echo Assuming port is already bound to DPDK
fi
exit 0
