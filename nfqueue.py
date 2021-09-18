#!/bin/python3 
#librairies import
from scapy.all import *
from netfilterqueue import NetfilterQueue

#whitelist packets who are deja filtered and accepted

#blacklist packets who are deja filtered and denied
blacklist=[]

#Function for filter
def Filtrage_paquet(packet):
    pkt=IP(packet.get_payload())
    ipsrc=pkt[IP].src
    ipdst=pkt[IP].dst

#var for blacklist / whitelist
    regles=[ipsrc,ipdst]

#show user ip src & dst
    if regles in whitelist:
        packet.accept()
    else:
        value = input("Voulez vous filtrer le paquet provenant de" + str(ipsrc) + " vers " + str(ipdst) + " [O/N]")
        if value =="O":
            packet.accept()
            whitelist.append(regles)
        else:
            packet.drop()
            blacklist.append(regles)

#Objet nfqueue
nfqueue = NetfilterQueue()

#call filter function for put packets on the first queue
nfqueue.bind(1, Filtrage_paquet)

try:
    print ('i love the smell of packets in the morning')
    nfqueue.run()
    exit()
except KeyboardInterrupt:
    exit()
    pass
