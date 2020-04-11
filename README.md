# Plan9 PING utility written in Go

This a Go reimplementation of the `ping` program from Plan9 operating system written in Go.
I tried to keep the program internal structure as close as possible to the original, modifying only the necessary parts in order to have the program running properly.

You can find the original source here: https://9p.io/sources/plan9/sys/src/cmd/ip/ping.c

## Usage

You need to run this program as root (or set `setuid` bit)

```
sudo ./ping -n 4 google.com
sending 4 64 byte messages 1000 ms apart to 216.58.209.78
0: rtt 20756943 µs, avg rtt 20756943 µs, ttl = 55
1: rtt 20284438 µs, avg rtt 20520690 µs, ttl = 55
2: rtt 20032185 µs, avg rtt 20357855 µs, ttl = 55
3: rtt 21819321 µs, avg rtt 20723221 µs, ttl = 55
```

## Instructions

From http://man.cat-v.org/plan_9/8/ping:

```
     DESCRIPTION
          Ping sends ICMP echo request messages to a system.  It can
          be used to determine the network delay and whether or not
          the destination is up.  By default, a line is written to
          standard output for each request.  If a reply is received
          the line contains the request id (starting at 0 and incre-
          menting), the round trip time for this request, the average
          round trip time, and the time to live in the reply packet.
          If no reply is received the line contains the word "lost",
          the request id, and the average round trip time.

          If a reply is received for each request, ping returns suc-
          cessfully. Otherwise it returns an error status of "lost
          messages".

          The options are:

          6    force the use of IPv6's ICMP, icmpv6, instead of IPv4's
               ICMP.  Ping tries to determine which version of IP to
               use automatically.

          a    adds the IP source and destination addresses to each
               report.

          f    send messages as fast as possible (flood).

          i    sets the time between messages to be interval millisec-
               onds, default 1000 ms.

          l    causes only lost messages to be reported.

          n    requests that a total of count messages be sent,
               default 32.

          q    suppresses any output (i.e. be quiet).

          r    randomizes the delay with a minimum extra delay of 0 ms
               and a maximum extra delay of the selected interval.

          s    sets the length of the message to be size bytes, ICMP
               header included.  The size cannot be smaller than 32 or
               larger than 8192.  The default is 64.

          w    sets the additional time in milliseconds to wait after
               all packets are sent.
```