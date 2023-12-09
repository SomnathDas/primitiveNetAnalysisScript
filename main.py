# Custom Lib
from sharkrecon import UnwireShark
from sharkrecon import PictureTheData

# External Libs
import pandas as pd

# Built-in Libs
import os

### Main Logic ###

# Checking if the .csv file (which is supposed to created on first run) is present or not
# This is purely done for performance reasons
# Since analysis of large capture file requires different set of rules and tools.
# Make sure whenever you make changes to what "data" you want to get out of packets
# Always delete "to_analyze.csv" file, so that it can stay in tuned with new data

if os.path.exists("to_analyze.csv"):
    pass
else:
    # Instantiating object of UnwireShark custom class with pcap "filename"
    myPcap = UnwireShark("HoneyBOT.pcap")
    # Calling getPacketsData method to get the required data
    packetsData = myPcap.getPacketsData()
    # Saving the parsed wireshark data as "csv" file
    pd.DataFrame(packetsData).to_csv(
        "to_analyze.csv", sep=",", index=False, encoding="utf-8"
    )

# Instantiating object of PictureTheData custom class with csv "filename"
myDf = PictureTheData("to_analyze.csv")

myDf.showIPFreqGraph()

myDf.showProtocolFreqGraph()

myDf.showTimeVsRequestGraph()

print(myDf.extractPlainTextData())
