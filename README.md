# NFQUEUE
Project created following a request from my Advanced System Security teacher at the École Supérieure de Génie Informatique.

The script is written in Python 3, it uses the libraries :
- Scapy : For package manipulation.
- Netfilterqueue : For filtering packets using the Netfilter Firewall and the Queue option in order to put them on hold for the time of a decision..

<p align="center">
  <img width="450" height="370" src="Schéma_NFQUEUE.png">
</p>

Currently a manual action from a user is needed to filter the packages one by one.
Whitelist / blacklist are set up in order to not have requests for action to a user on already processed packets.

TO DO :
- Implementation of threads to process packets on several queues.
- Implementation of a GUI.
