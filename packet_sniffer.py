from tkinter import *
from Network.ethernet import *
from Network.icmp import *
from Network.ipv4 import *
from Network.pcap import *
from Network.tcp import *
from Network.udp import *

root = Tk()
root.title("Packet Sniffer")
root.geometry('800x600')
root.resizable(0, 0)

label1 = Label(root, text="Packet Sniffer", fg="red")
label1.pack(fill=X, padx=10)

scroll = Scrollbar(root)
listbox = Listbox(root, height=28, yscrollcommand=scroll.set)

listbox.pack(fill=X)
scroll.pack()


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


def packetSniffer():
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        eth = Ethernet(raw_data)

        listbox.insert(END, '\nEthernet Frame:')
        listbox.insert(END, TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            listbox.insert(END, TAB_1 + 'IPv4 Packet:')
            listbox.insert(END, TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            listbox.insert(END, TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

            # ICMP
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)
                listbox.insert(END, TAB_1 + 'ICMP Packet:')
                listbox.insert(END, TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                listbox.insert(END, 'ICMP Data:')
                listbox.insert(END, format_multi_line(DATA_TAB_3, icmp.data))

            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                listbox.insert(END, TAB_1 + 'TCP Segment:')
                listbox.insert(END, TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                listbox.insert(END, TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                listbox.insert(END, TAB_2 + 'Flags:')
                listbox.insert(END, TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                listbox.insert(END, TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                if len(tcp.data) > 0:

                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        listbox.insert(END, TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                listbox.insert(END, DATA_TAB_3 + str(line))
                        except:
                            listbox.insert(END, format_multi_line(DATA_TAB_3, tcp.data))
                    else:
                        listbox.insert(END, TAB_2 + 'TCP Data:')
                        listbox.insert(END, format_multi_line(DATA_TAB_3, tcp.data))

            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
                listbox.insert(END, TAB_1 + 'UDP Segment:')
                listbox.insert(END, TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size) )

            # Basics IPv4
            else:
                listbox.insert(END, TAB_1 + 'Basics IPv4 Data:')
                listbox.insert(END, format_multi_line(DATA_TAB_2, ipv4.data))

        else:
            listbox.insert(END, 'Ethernet Data:')
            listbox.insert(END, format_multi_line(DATA_TAB_1, eth.data))

        root.update()

    pcap.close()


button1 = Button(root, text="Initiate", fg="Blue", command=packetSniffer)
button1.pack(side=LEFT)
root.mainloop()








