
# hdrgrab

hdrgrab sniffs HTTP messages off the wire and writes them into a 
[HAR](http://www.softwareishard.com/blog/har-12-spec/) file.


## Installing hdrgrab

First you'll need [Node](http://nodejs.org/) and its package manager, 
[npm](http://npmjs.org/). 

Then, hdrgrab can be installed with npm like this:

  > sudo npm -g install hdrgrab

which will install dependencies automatically. 

Under the covers, hdrgrab relies upon
 [node_pcap](https://github.com/mranney/node_pcap/) and
 [optimist](https://github.com/substack/node-optimist). 


## Using hdrgrab

hdrgrab

Start it up like this:

  > hdrgrab

which will sniff on port 80 and dump headers into the current directory.

  > hdrgrab 8000

will sniff on port 80.

On some operating systems, you may need to specify the interface to listen
on. For example:

  > hdrgrab 8000 eth0
  
and in some cases, you may need permission to listen to the device, making 
the appropriate command line something like:

  > sudo hdrgrab 8000 eth0



## Installation Problems?

### libpcap

If npm complains about problems with pcap, like this:

    npm ERR! Failed at the pcap@0.2.7 install script.

it usually means that it couldn't find libpcap when building. See the
instructions here: <https://github.com/mranney/node_pcap>. 

On my OSX machine, I have to build like this (becoming root first):

  > CXXFLAGS=-I/opt/local/include npm -g install hdrgrab
  
because my pcap headers are in a non-standard place (thanks to MacPorts). 
YMMV.


## Contact

Mark Nottingham <mnot@mnot.net>

http://github.com/mnot/hdrgrab/


