# Introduction #

This is a description of the NAT traversal techniques used in this project.

# Details #
To enable the most effective NAT traversal routines we use some Kademlia tricks. This is done mainly to enable us to pass freely and easily the rendezvous nodes for each contact (if required) amongst other nodes.

### Rendezvous Requirements ###

For a node to be a rendezvous-capable node, it must be directly contactable from any node on the network. These nodes will be one of the following:
  * Directly connected to the net
  * Behind a full cone type NAT device
  * Behind a NAT router that's port-forwarded to the node
  * Be connected via UPnP (HTTP over UDP - with no authentication mechanism and turned off by many manufacturers nowadays) or DPWS1 or NAT-PMP1 or some other router mapping protocol

### Rendezvous Procedure ###
To detect which types we are dealing with, we have a couple of neat tricks.  Consider the scenario where:
  * Node A wants to connect
  * Node B is a boostrap node (of one of the above types)
  * Node C is any other random node which B knows of

The procedure is:

  1. A sends B a special boostrap message
  1. B asks C to try to ping A
  1. If ping fails, B asks C to try a rendezvous to A with B acting as rendezvous node
    1. If rendezvous fails, B replies "NOT connected" to A (later we can do tunneling for clients if needed) - END
    1. If rendezvous succeeds, B replies "RENDEZVOUS connected" to A (included in the response is A's external IP and Port) - END
  1. If C's ping to A succeeds, B replies "DIRECTLY connected" to A (Directly connected nodes have no rendezvous IP or Port in their contact tuple) - END

Now normal Kademlia boostrapping happens, i.e. A executes an iterative find\_node on his own Kademlia ID to populate his routing table and disseminate his details to other nodes' routing tables.



---

The standard DPWS is a candidate successor for UPnP. It solves many of the problems of UPnP. A DPWS client is included in Microsoft Windows Vista as part of the Windows Rally technologies.