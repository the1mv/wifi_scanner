import subprocess
import re
import csv
from datetime import datetime

class TempObject:
    def __init__(self, ssid, bssid, signal, radio, band, channel, auth, cipher):
        self.ssidName = ssid
        self.bssid_val = bssid
        self.signalStrength = signal
        self.radio_type = radio
        self.bandVal = band
        self.channel_num = channel
        self.authMethod = auth
        self.cipher_type = cipher

class DataProcessor:
    def __init__(self):
        self.networkHashMap = {}
        self.dataStack = []
        self.flagCheck = False

    def executeSystemCommand(self):
        try:
            cmd_output = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                encoding="utf-8",
                errors="ignore"
            )
            self.flagCheck = True if len(cmd_output) > 0 else False
            return cmd_output if self.flagCheck else ""
        except Exception as e:
            print("Error:", e)
            return ""

    def processAndParseData(self, raw_text):
        try:
            if not self.flagCheck:
                return

            blocks = [b.strip() for b in raw_text.split("\nSSID ") if b.strip()]
            
            for block in blocks[1:] if len(blocks) > 1 else []:
                lines = [line.strip() for line in block.split("\n") if line.strip()]
                
                ssid_extract = (lambda l: l.split(":", 1)[1].strip() if ":" in l else "Hidden")(lines[0])
                auth_val = "Unknown"
                cipher_val = "Unknown"
                
                current_bssid = None
                temp_dict = {}

                for line in lines[1:]:
                    if line.startswith("Authentication"):
                        auth_val = (lambda x: x.split(":", 1)[1].strip())(line)
                    elif line.startswith("Encryption"):
                        cipher_val = (lambda x: x.split(":", 1)[1].strip())(line)
                    elif line.startswith("BSSID"):
                        current_bssid = (lambda x: x.split(":", 1)[1].strip())(line)
                        temp_dict[current_bssid] = {
                            "signal": "0%",
                            "radio": "N/A",
                            "band": "N/A",
                            "channel": "0"
                        }
                    elif current_bssid is not None:
                        if line.startswith("Signal"):
                            temp_dict[current_bssid]["signal"] = line.split(":", 1)[1].strip()
                        elif line.startswith("Radio type"):
                            temp_dict[current_bssid]["radio"] = line.split(":", 1)[1].strip()
                        elif line.startswith("Band"):
                            temp_dict[current_bssid]["band"] = line.split(":", 1)[1].strip()
                        elif line.startswith("Channel"):
                            temp_dict[current_bssid]["channel"] = line.split(":", 1)[1].strip()

                for bssid_key, specs in temp_dict.items():
                    obj = TempObject(
                        ssid_extract,
                        bssid_key,
                        specs["signal"],
                        specs["radio"],
                        specs["band"],
                        specs["channel"],
                        auth_val,
                        cipher_val
                    )
                    self.networkHashMap[bssid_key] = obj
                    self.dataStack.append(bssid_key)

        except Exception as e:
            print("Error:", e)

class OutputManager:
    def __init__(self, processor_instance):
        self.procObj = processor_instance
        self.exportFlag = False

    def getSortedKeys(self):
        try:
            return sorted(
                [k for k in self.procObj.dataStack],
                key=lambda k: int(re.sub(r"\D", "", self.procObj.networkHashMap[k].signalStrength) or 0),
                reverse=True
            )
        except Exception as e:
            print("Error:", e)
            return []

    def displayResult(self):
        try:
            header = f"{'SSID':<25} | {'BSSID':<18} | {'Signal':<7} | {'Channel':<7} | {'Band':<10} | {'Radio':<10} | {'Auth':<15} | {'Encryption':<10}"
            print(header)
            print("-" * len(header))

            for key in self.getSortedKeys():
                item = self.procObj.networkHashMap.get(key)
                if item:
                    row = (
                        f"{item.ssidName[:25]:<25} | "
                        f"{item.bssid_val:<18} | "
                        f"{item.signalStrength:<7} | "
                        f"{item.channel_num:<7} | "
                        f"{item.bandVal:<10} | "
                        f"{item.radio_type:<10} | "
                        f"{item.authMethod[:15]:<15} | "
                        f"{item.cipher_type:<10}"
                    )
                    print(row)
        except Exception as e:
            print("Error:", e)

    def exportDataToCsv(self, file_name="wifi_scan_report.csv"):
        try:
            sorted_keys = self.getSortedKeys()
            self.exportFlag = True if len(sorted_keys) > 0 else False
            if not self.exportFlag:
                print("No data to export.")
                return

            timestamp_val = (lambda d: d.strftime("%Y-%m-%d %H:%M:%S"))(datetime.now())
            
            with open(file_name, mode="w", newline="", encoding="utf-8") as csv_file:
                writer_obj = csv.writer(csv_file)
                writer_obj.writerow(["Timestamp", "SSID", "BSSID", "Signal", "Channel", "Band", "Radio_Type", "Authentication", "Encryption"])
                
                rows_to_write = [
                    [
                        timestamp_val,
                        self.procObj.networkHashMap[k].ssidName,
                        self.procObj.networkHashMap[k].bssid_val,
                        self.procObj.networkHashMap[k].signalStrength,
                        self.procObj.networkHashMap[k].channel_num,
                        self.procObj.networkHashMap[k].bandVal,
                        self.procObj.networkHashMap[k].radio_type,
                        self.procObj.networkHashMap[k].authMethod,
                        self.procObj.networkHashMap[k].cipher_type
                    ]
                    for k in sorted_keys if k in self.procObj.networkHashMap
                ]
                writer_obj.writerows(rows_to_write)
                
            print(f"\nExported {len(rows_to_write)} records to {file_name}")
        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    mainProcessor = DataProcessor()
    raw_data = mainProcessor.executeSystemCommand()
    mainProcessor.processAndParseData(raw_data)
    
    viewer = OutputManager(mainProcessor)
    viewer.displayResult()
    viewer.exportDataToCsv("wifi_scan_results.csv")