#!/bin/python3
# Julien HOURY. 
#Import des librairies
from scapy.all import *
from netfilterqueue import NetfilterQueue

#whitelist des paquets deja filtré & accepté 
whitelist=[]

#blacklist des paquets deja filtré & refusé
blacklist=[]

#Definitiion de la fonction de filtrage
def Filtrage_paquet(packet):
    pkt=IP(packet.get_payload())
    ipsrc=pkt[IP].src
    ipdst=pkt[IP].dst

#variable pour blacklist / whitelist
    regles=[ipsrc,ipdst]

#montre a l'utilisateur l'ip src et dst du paquet
#boucle pour blacklist / whitelist
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

#fait appel a la fonction de filtrage pour mettre les paquets sur la queue numero 1
nfqueue.bind(1, Filtrage_paquet)

try:
    print ('NFQUEUE en écoute')
    nfqueue.run()
    exit()
except KeyboardInterrupt:
    exit()
    pass
