# Author @SomnathDas
# External Libs
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

from time import strftime, localtime


# Utilities
def clear_line(n=1):
    LINE_UP = "\033[1A"
    LINE_CLEAR = "\x1b[2K"
    for i in range(n):
        print(LINE_UP, end=LINE_CLEAR)


# Main Class
class UnwireShark:
    def __init__(self, filename) -> None:
        self.captureFile = pyshark.FileCapture(filename, keep_packets=False)

    def getPacketsData(self):
        data = []
        for idx, packet in enumerate(self.captureFile):
            print("[*] Processing: {}".format(idx))
            clear_line()

            if hasattr(packet, "ipv6") and hasattr(packet, "udp"):
                data.append(
                    {
                        "src": packet.ipv6.src,
                        "dst": packet.ipv6.dst,
                        "proto": packet.highest_layer,
                        "time": strftime(
                            "%Y-%m-%d %H:%M:%S",
                            localtime(packet.sniff_time.timestamp()),
                        ),
                        "data": packet.udp.payload,
                    }
                )

            elif hasattr(packet, "udp") and hasattr(packet, "ip"):
                data.append(
                    {
                        "src": packet.ip.src,
                        "dst": packet.ip.dst,
                        "proto": packet.highest_layer,
                        "time": strftime(
                            "%Y-%m-%d %H:%M:%S",
                            localtime(packet.sniff_time.timestamp()),
                        ),
                        "data": packet.udp.payload,
                    }
                )

            elif (
                hasattr(packet, "ip")
                and hasattr(packet.ip, "src")
                and hasattr(packet.ip, "dst")
            ):
                if not (hasattr(packet, "data") or hasattr(packet, "port")):
                    data.append(
                        {
                            "src": packet.ip.src,
                            "dst": packet.ip.dst,
                            "proto": packet.highest_layer,
                            "time": strftime(
                                "%Y-%m-%d %H:%M:%S",
                                localtime(packet.sniff_time.timestamp()),
                            ),
                            "data": "Empty",
                        }
                    )

                else:
                    data.append(
                        {
                            "src": packet.ip.src,
                            "dst": packet.ip.dst,
                            "port": packet.tcp.port,
                            "proto": packet.highest_layer,
                            "time": strftime(
                                "%Y-%m-%d %H:%M:%S",
                                localtime(packet.sniff_time.timestamp()),
                            ),
                            "data": packet.tcp.payload,
                        }
                    )

            elif hasattr(packet, "arp"):
                data.append(
                    {
                        "src": packet.arp.src_proto_ipv4,
                        "dst": packet.arp.dst_proto_ipv4,
                        "port": "Empty",
                        "proto": packet.highest_layer,
                        "time": strftime(
                            "%Y-%m-%d %H:%M:%S",
                            localtime(packet.sniff_time.timestamp()),
                        ),
                        "data": "Empty",
                    }
                )

        return data


# Main Class
class PictureTheData:
    def __init__(self, csv_filepath) -> None:
        self.df = pd.read_csv(csv_filepath)

    def showIPFreqGraph(self):
        x = np.array((self.df["src"].unique()))
        y = np.array(self.df["src"].value_counts())

        plt.ylabel("No. of Requests")

        plt.xticks(rotation=45)
        plt.subplots_adjust(bottom=0.25)

        plt.bar(x, y)
        plt.show()

    def showProtocolFreqGraph(self):
        x = np.array((self.df["proto"].unique()))
        y = np.array(self.df["proto"].value_counts())

        plt.bar(x, y)
        plt.show()

    def showTimeVsRequestGraph(self):
        x = self.df.groupby(["time", "proto"]).size().unstack(fill_value=0)

        x.plot(kind="bar", stacked=True)

        plt.title("Protocols making up total requests made at a given time")
        plt.xlabel("Date and Time")
        plt.ylabel("Fraction of Protocols in Req/Res")

        plt.xticks(rotation=45)
        plt.subplots_adjust(bottom=0.25)

        plt.show()

    def extractPlainTextData(self):
        final = []
        for idx, i in enumerate(self.df["data"]):
            if i == "Empty":
                pass
            else:
                ascii_data = bytearray.fromhex(i.replace(":", " ")).decode(
                    errors="replace"
                )
                src_data = self.df["src"][idx]
                final.append([src_data, ascii_data])

        return pd.DataFrame(final, columns=["IP Address", "PlainText Data (UTF-8)"])
