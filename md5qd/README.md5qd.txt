TCP-MD5 daemon for Linux, using Netfilter userspace QUEUE and modify.
---------------------------------------------------------------------

Warning:
--------

- Experimental daemon, may very well urinate in your flower pots and 
  asphyxiate your cat.
- Configuration syntax is *evolving* and almost certainly *will*
  change (in particular, to better integate with normal BGP syntax).
  I.e. Be careful when upgrading - no forward/backward compatibility
  of configuration file syntax should be assumed *AT ALL*.
- This daemon does *NOT* configure netfilter, you must do that yourself
  and it's easy to get wrong.


Compiling:
----------

- You need iptables development headers and the netfilter kernel
  headers. I.e. linux/netfilter.h and libipq.h must both be present
  under the standard compiler include search path.
- After that, just run configure, md5qd will be enabled automatically
  when Linux is the target system and those headers are present.

Configuration:
--------------

- configure the daemon via /path/to/quagga/conf/md5qd.conf (or via the
  telnet interface, if enabled - it listens on port 2609 by default).
  Sample:
  
  md5qd
   neighbour 192.168.0.1 mode tcp-md5 wobble
   neighbour 192.168.1.1 mode tcp-md5 wibble

- configure netfilter to send TCP packets to these hosts with either
  source or destination port of 179 (BGP) to the 'QUEUE' target:
  
  # for H in 192.168.0.1 192.168.1.1 ; do \
    iptables -A OUTPUT -p tcp -d ${H} --dport 179 -j QUEUE; \
    iptables -A OUTPUT -p tcp -d ${H} --sport 179 -j QUEUE; done
  
  If you wish to also verify the TCP-MD5 on /received/ packets, do the
  same, but for packets received from those hosts:
  
  # for H in 192.168.0.1 192.168.1.1 ; do \
    iptables -A INPUT -p tcp -s ${H} --dport 179 -j QUEUE; \
    iptables -A INPUT -p tcp -s ${H} --sport 179 -j QUEUE; done
  
  It may be easier to create a seperate chain, direct TCP BGP
  source/destination port and have the chain list the IPs just once,
  for the direction concerned, one can then also set a default action
  for BGP packets from other hosts (ACCEPT/REJECT).


Running md5qd:
--------------

- ensure the 'ip_queue' module has been loaded.
- start md5qd

- md5qd may be restarted at will, bgpd does *not* need to be restarted.
  - though, if md5qd is not running, it can't pass judgement on received
    packets obviously - which may lead to your sessions dropping.
  - presuming correct configuration, BGP sessions should not notice MD5
    restarts (TCP-MD5 is stateless - one of the reasons it's pretty
    poor security wise), TCP will take care of retrying packets.


Verifying md5qd functionality:
------------------------------

- tcpdump can verify TCP-MD5 if compiled with crypto support:

   tcpdump -M wibble host 192.168.1.1 and port bgp

- md5qd can print out debug, set 'debug md5qd' and watch the logs
  (or 'terminal monitor' from the telnet interface).

- if md5qd denies received packets, the packet will never reach bgpd.

- if you have problems, make sure you loaded the 'ip_queue' module
  *before* starting md5qd.
