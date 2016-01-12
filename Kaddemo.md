# Introduction #

kaddemo is a cli program able to act as a Kademlia node.  Multiple instances of the program can be run to form a Kademlia network.  It serves as a demo program to drive the maidsafe-dht library, allowing the user to investigate the network implementation's performance.

# maidsafe test network #
We have set up some nodes as a test network. The information of the bootstrapping nodes is in a file ([bootstrapping\_nodes.txt](http://maidsafe-dht.googlecode.com/files/bootstrapping_nodes.txt)) in the Downloads section. See below for instruction to start a node.  You can start a node as a client and no values will be stored into it, but it will be able to store values to the network and find values from it.

# Getting Started #
The kaddemo program can play one of two roles - either a node (an active participant in the network), or a client (doesn't join the network, but is capable of storing to and retrieving from the network at the user's behest).

To start the first node:

```
./kaddemostatic -p 5000 --externalip 192.168.1.115 --externalport 5000 --noconsole --nodeinfopath .
```

Whereby 5000 is the port this node is to operate on and 192.168.1.1 is the IP of the machine the node is launched on.  `--noconsole` makes this node unable to accept input from the user (disables any client funtionality) and `--nodeinfopath` gives the node a path to write all the nodes it knows to a file to allow it to bootstrap the second time it starts up.

This first node's `.kadconfig` file can be used to allow subsequent nodes to bootstrap.

```
mkdir KnodeInfo5001
cp .kadconfig KnodeInfo5001/
./kaddemostatic -p 5001 -k KnodeInfo5001/.kadconfig
```

assuming the second node is to be started on port 5001.

To check the two nodes can see each other, take the Node\_id from the output of the first node and issue a ping from the second.

```
pingnode 00e3f94f46aa7deec506976924da25c3dd71cc19f6a898f0694c34663352453b8eaf72a9420a8b43c8f9151c63763a8e193d6fe8ae6b76c37405dc0fd260d644
```

where 00e3f94f46aa7deec506976924da25c3dd71cc19f6a898f0694c34663352453b8eaf72a9420a8b43c8f9151c63763a8e193d6fe8ae6b76c37405dc0fd260d644 is the first node's Node\_id.

From here, more nodes can be started, either on the same machine or on different machines.  The more nodes on the network, the more stable it will become and the more correct results will be.

# Details #

Starting a network.


First node of the network
run: ./kaddemostatic --port 

&lt;port&gt;

 --externalip 

&lt;ip&gt;

 --extrenalport

&lt;extport&gt;





&lt;port&gt;

: the local port where the node will start listening.  Value is optional, if no argument is passed, a random port is selected.


&lt;externalip&gt;

: external ip to where the node is going to be contacted. If this is a local network, this address is the local ip of the pc where the node is.


&lt;externalport&gt;

: external port to where the node is going to be contacted. If this is a local network, this port is the same as 

&lt;port&gt;



optional arguments:
--upnp:  starts upnp to map an external port.  If it fails to map, the node fails to join.

--port\_fw: to indicate if the external port has been manually forwarded.
--noconsole: does not show the interface to perform kademlia operations (ping a node, store a value, load a value) with this node
--logflepath 

&lt;path&gt;

: path to log file
--verbose: log is printed to std::cerr
--kadconfigfile 

&lt;pathname&gt;

: complete pathname of the kadconfig file. This can be used to rejoin the node if it has left the network.
--refresh\_time 

&lt;time&gt;

: number of minutes of the interval to refresh values stored in the node.


Subsequent nodes:
run: ./kaddemostatic --port 

&lt;port&gt;

 --bs\_ip <bootstrap ip> --bs\_port<bootstrap port> --bs\_id <boostrap id> --bs\_local\_ip<bootstrap local ip> --bs\_local\_port <boostrap local port>




&lt;port&gt;

: the local port where the node will start listening.  Value is optional, if no argument is passed, a random port is selected.
<bootstrap ip>: external ip of the bootstrapping node.
<bootstrap port>: external port of the bootstrapping node.
<bootstrap id>: node id of the bootstrapping node
<bootstrap local ip>: local ip of the bootstrapping node.
<bootstrap local port>: local port of the bootstrapping node.

optional parameters:
--kadconfigfile 

&lt;pathname&gt;

: complete pathname of the kadconfig file.  If it has bootstrapping contacts, command line arguments with info of the bootstrapping nodes can be ommited. This can be used to rejoin the node if it has left the network.
--port\_fw: to indicate if the external port has been manually forwarded.
--noconsole: does not show the interface to perform kademlia operations (ping a node, store a value, load a value) with this node
--logflepath 

&lt;path&gt;

: path to log file
--verbose: log is printed to std::cerr
--client: the node acts only as a client, i.e. it does not store any values and its id is not stored in other nodes routing table.  This option can not be used with the noconsole option.
--refresh\_time 

&lt;time&gt;

: number of minutes of the interval to refresh values stored in the node.
--nodeinfopath 

&lt;path&gt;

: path to where .kaconfig file is written with the nodes info.