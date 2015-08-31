# Leopard Flower personal firewall for Linux (LPFW)

LPFW gives the user control over which applications are allowed to use the
network.
It comes with a GUI.

These instructions apply specifically to Ubuntu 14.04 64-bit but are very
likely to work on other Linux distributions.
Please note that on 32-bit Linuxes lpfw may function incorrectly.

Install all dependencies:

```Shell
sudo apt-get install make g++ libnetfilter-queue-dev libnetfilter-conntrack-dev libcap-dev python-qt4
```

Compile:
```Shell
make
```

Quick start:
Run `lpfw` as root. Run python `gui/gui.py` as regular user.

## Command line arguments

These can be also seen with `lpfw --help`.

    --rules-file=
    File to which rules are commited (default: /etc/lpfw.rules)

    --logging_facility=
    Where to write logs. Possible values stdout(default), file, syslog

    --log-file=
    If --logging_facility=file, then this is the file to which to write logging information. Default /tmp/lpfw.log

    --pid-file=
    Pidfile which prevents two instances of lpfw being launched at the same time. Default /var/log/lpfw.pid

    --log-info=
    --log-traffic=
    --log-debug=
    Enables different levels of logging. Possible values 1 or 0 for yes/no. Default: all three 1.

## Known issues

* Only IPv4.
* Only TCP and UDP. LPFW will drop any other protocol packets. To prevent dropping, add a rule which must preceed the LPFW's NFQUEUE rules, e.g.
* iptables -I OUTPUT 1 -p udplite -j ACCEPT
* If LPFW crashes, run "sudo iptables -F" to disable all rules.



## The rest of this file's contents is technical information for system administrators and advanced users

### Traffic logging format

An example of traffic log's line:

    <UDP remote 80.233.253.203:40320 local 36340   /home/wwwwww/apps/skype_static-2.2.0.35/skype 2150 allow
    1 2    3             4        5    6     7                         8                           9    10

1. direction of traffic "<" outgoing, ">" incoming
2. Protocol type UDP / TCP
3.
4. IP address of remote machine
5. port of remote machine
6.
7. local port
8. Path to the executable which initiated the packet or for which the packet was destined
9. Process ID of the executable
10. Action taken by LPFW with regard to this packet


### Architecture

LeopardFlower (LPFW) utilizes a facility provided by netfilter whereby all outgoing and incoming packets which initiate a new connection are delivered to LPFW for decision on whether to drop them or accept them. LPFW sets up a rule with iptables similar to
`iptables -A OUTPUT -j NFQUEUE --queue-num 11220`
and installs a callback (using libnetfilter_queue) which is notified whenever a packet hits the NFQUEUE (NFQ). The fact that LPFW doesn't need to process every single packet but only those which initiate new connections, significantly decreases LPFW's CPU consumption.

Upon start up, LPFW read a rules file which contains Internet access permissions per application. Based upon these rules, whenever a new packet hits NFQ, LPFW decides whether to allow or deny Internet access or whether to ask the user what to do if no rule for the application in question has yet been defined.

In order to establish a correlation between a packet which hit nfq and the application which sent it, LPFW does the following:

1. For an outgoing packet - extract source port  (for an incoming packet - extract destination port) and look up in /proc/net/tcp to see which socket corresponds to the port.
2. Having found the socket, scan /proc/<PID>/fd to see which process owns the socket
3 Finally extract the application name from /proc/<PID>/exe

LPFW sets a unique netfilter mark on all connections of a specific app. This enables LPFW to instantly halt all app's Internet activity if user chooses so. In order to set such a netfilter mark, LPFW uses libnetfilter_conntrack library.


## Security

LPFW strips itself of all capabilities except the following:

CAP_SYS_PTRACE (to readlink() root's links in /proc)
CAP_NET_ADMIN (to use netfilter_queue and netfilter_conntrack)
CAP_DAC_READ_SEARCH (to scan all users' /proc/ entries)

See `man 7 capabilities` for more information on capabilities.
