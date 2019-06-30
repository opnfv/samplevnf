egrep  '^[0-9]{4}|^[0-9]+\.' prox.log | text2pcap -q - - | tshark -r -
