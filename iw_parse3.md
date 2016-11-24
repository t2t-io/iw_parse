iw_parse3
=========

Derived from `iw_parse.py`, but add CSV outputs to stdout with hex characters for easier transmission.

Here are steps to setup and run on any embedded Linux device (with same prerequisites as `iw_parse.py`):

```bash
$ # Checkout latest codes to /opt/iw_parse
$ git clone https://github.com/t2t-io/iw_parse.git /opt/iw_parse
$ 
$ # Setup required environment variables:
$ export WIRELESS_ADAPTER=$(ifconfig | grep "^wlan" | awk '{print $1}')
$ export QUALITY_THRESHOLD=20
$ 
$ # Run with socat as TCP daemon
$ socat -d -d TCP4-LISTEN:5555,fork,tcpwrap=script EXEC:/opt/iw_parse/iw_parse3.py,pty
```

The last line is to setup a TCP daemon listening to port 5555. For any incoming TCP connection to port 5555, socat shall run `/opt/iw_parse/iw_parse3.py`, redirect the stdout outputs to that TCP connection, and then close that connection.

For example, open another terminal, and run this command:

```bash
$ socat - tcp-connect:127.0.0.1:5555
0
F835DD7E09A6	9	36	B8	0	4348545F49303430475731
B0487ADC0004	6	4D	C8	1	4D4153434F54
00F76FD1BAF0	B	45	C2	0	4D69636861656C27732057692D4669204E6574776F726B
000C437097EF	1	64	F2	0	E890ACE683A1E79A84E4B8ADE6968753534944
9801A7E71638	1	56	CE	0	617034743274
001DAA83E10C	3	64	D8	0	617034743274
C4B301DE421C	6	64	DA	0	6170347432742D3547487A
0C722C1F9122	6	5E	D4	1	6170347432742D6775657374
74DA384E4A9E	2	45	C2	0	737477612D6E
```

1st line of output is to indicate the execution is successful or not. `0` is success, while other non-zero value is failure.

Other lines are CSV format output, separaed by TAB, with following columns:

- Mac address of wireless access point
- Wireless channel (in hex)
- Wireless quality (in hex)
- Wireless signal level (added with 256, and format is hex)
- SSID of the wireless access point (UTF8 bytes in hex representation)