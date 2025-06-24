import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox, filedialog
import socket
import uuid
import threading
import json
import time
import os
import random
import base64
from rsa_crypto import (
    encrypt_message,
    decrypt_message,
    load_private_key,
    get_public_key_string,
    load_public_key_from_pem
)
from udp_broadcaster import send_udp_broadcast

PORT = 5005
BUFFER_SIZE = 4096
GATEWAY_LIST_PATH = "gateway_list.txt"

def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"
    finally:
        s.close()

def generate_random_ip():
    return f"{random.randint(11, 230)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

class PrivateChatWindow:
    def __init__(self, parent_gui, target_ip, target_nick, target_pubkey, my_nick):
        self.parent_gui = parent_gui
        self.target_ip = target_ip
        self.target_nick = target_nick
        self.target_pubkey = target_pubkey
        self.my_nick = my_nick
        self.window = tk.Toplevel(parent_gui.root)
        self.window.title(f"Özel Sohbet: {target_nick}")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        self.chat_area = scrolledtext.ScrolledText(self.window, state='disabled', width=55, height=16)
        self.chat_area.pack(padx=10, pady=10)
        self.entry = tk.Entry(self.window, width=40)
        self.entry.pack(side=tk.LEFT, padx=(10, 0), pady=(0, 10), expand=True, fill=tk.X)
        send_btn = tk.Button(self.window, text="Gönder", command=self.send_private_message)
        send_btn.pack(side=tk.LEFT, padx=(5, 10), pady=(0, 10))
        file_btn = tk.Button(self.window, text="📎 Dosya", command=self.send_private_file)
        file_btn.pack(side=tk.LEFT, padx=(0, 10), pady=(0, 10))

    def on_close(self):
        key = (self.target_ip, self.target_nick)
        if key in self.parent_gui.private_chats:
            del self.parent_gui.private_chats[key]
        self.window.destroy()

    def append(self, msg):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, msg + "\n")
        self.chat_area.yview(tk.END)
        self.chat_area.config(state='disabled')

    def send_private_message(self):
        msg = self.entry.get()
        if not msg:
            return
        try:
            if self.target_pubkey is None:
                raise Exception("Karşı tarafın public anahtarı bulunamadı!")
            msg_id = str(uuid.uuid4())
            raw_bytes = msg.encode()
            chunk_size = 190  # RSA 2048-bit OAEP sınırı
            chunks = [raw_bytes[i:i+chunk_size] for i in range(0, len(raw_bytes), chunk_size)]
            total_parts = len(chunks)
            for i, chunk in enumerate(chunks):
                encrypted = encrypt_message(chunk.decode(errors='ignore'), self.target_pubkey)
                packet = {
                    "type": "private_message",
                    "payload": encrypted.hex(),
                    "msg_id": msg_id,
                    "timestamp": time.time(),
                    "part": i,
                    "total_parts": total_parts,
                    "sender": self.my_nick,
                    "target_ip": self.target_ip,
                    "fake_ip": self.parent_gui.spoofed_ip
                }
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(json.dumps(packet).encode(), (self.target_ip, PORT))
                time.sleep(0.01)
            self.append(f"{self.my_nick} (Siz): {msg}")
            self.entry.delete(0, tk.END)
        except Exception as e:
            self.append(f"[HATA] Gönderilemedi: {e}")

    def send_private_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()
            file_b64 = base64.b64encode(file_bytes).decode()
            file_name = os.path.basename(file_path)
            if self.target_pubkey is None:
                raise Exception("Karşı tarafın public anahtarı bulunamadı!")
            encrypted = encrypt_message(file_b64, self.target_pubkey)
            packet = {
                "type": "private_file",
                "filename": file_name,
                "payload": encrypted.hex(),
                "msg_id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "sender": self.my_nick,
                "target_ip": self.target_ip,
                "fake_ip": self.parent_gui.spoofed_ip
            }
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(json.dumps(packet).encode(), (self.target_ip, PORT))
            self.append(f"📎 Dosya gönderildi: {file_name}")
        except Exception as e:
            self.append(f"[HATA] Dosya gönderilemedi: {e}")

class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.user_map = {}
        self.private_key = None
        self.nickname = None
        self.my_ip = get_my_ip()
        self.is_gateway = False
        self.gateway_list = []
        self.seen_messages = {} 
        self.last_sent_msg = None
        self.msg_buffer = {}
        self.msg_meta = {}
        self.spoofed_ip = generate_random_ip()
        self.private_chats = {}  
        self.private_msg_buffer = {}  
        self.private_msg_meta = {}
        self.build_gui()
        self.setup_menu()
        self.ask_role()
        self.iface = "eth0"
        self.listener_thread = threading.Thread(target=self.start_udp_listener, daemon=True)
        self.listener_thread.start()

    def build_gui(self):
        self.root.title("🔐Anonim İnsanlar Chat 2025 ")

        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)

        left_frame = tk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.chat_area = scrolledtext.ScrolledText(left_frame, state='disabled', width=60, height=20)
        self.chat_area.pack(fill=tk.BOTH, expand=True)

        message_frame = tk.Frame(left_frame)
        message_frame.pack(fill=tk.X, pady=(10, 0))

        self.entry = tk.Entry(message_frame, width=45)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        send_button = tk.Button(message_frame, text="Gönder", command=self.send_message)
        send_button.pack(side=tk.RIGHT)

        right_frame = tk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=10)

        tk.Label(right_frame, text="Online Users", font=("Arial", 11, "bold")).pack()
        self.user_listbox = tk.Listbox(right_frame, width=25)
        self.user_listbox.pack(fill=tk.Y, expand=True, pady=(5, 0))
        self.user_listbox.bind('<Button-3>', self.show_private_menu)
        self.right_menu = tk.Menu(self.user_listbox, tearoff=0)
        self.right_menu.add_command(label="Özel Sohbet Başlat", command=self.start_private_chat)

    def show_private_menu(self, event):
        try:
            index = self.user_listbox.nearest(event.y)
            self.user_listbox.selection_clear(0, tk.END)
            self.user_listbox.selection_set(index)
            self.right_menu.post(event.x_root, event.y_root)
        except:
            pass

    def start_private_chat(self):
        try:
            index = self.user_listbox.curselection()[0]
            user_list = list(self.user_map.items())
            target_ip, (target_nick, target_pubkey) = user_list[index]
            if target_ip == self.my_ip or not target_pubkey:
                messagebox.showinfo("Uyarı", "Kendinizle veya offline kullanıcıyla özel sohbet başlatamazsınız.")
                return
            key = (target_ip, target_nick)
            
            if key not in self.private_chats or not self.private_chats[key].window.winfo_exists():
                chat_win = PrivateChatWindow(self, target_ip, target_nick, target_pubkey, self.nickname)
                self.private_chats[key] = chat_win
            else:
                try:
                    self.private_chats[key].window.lift()
                except:
                    
                    chat_win = PrivateChatWindow(self, target_ip, target_nick, target_pubkey, self.nickname)
                    self.private_chats[key] = chat_win
        except Exception as e:
            messagebox.showerror("Hata", f"Özel sohbet başlatılamadı: {e}")

    def setup_menu(self):
        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)

        filemenu.add_command(label="Generate Keys", command=self.generate_keys)
        filemenu.add_command(label="Connect to Network", command=self.connect_to_network, state=tk.DISABLED)
        filemenu.add_command(label="Disconnect from Network", command=self.disconnect_from_network, state=tk.DISABLED)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.root.quit)

        self.filemenu = filemenu
        menubar.add_cascade(label="File", menu=filemenu)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About", command=lambda: messagebox.showinfo("Hakkında", "YUNUS EMRE KILIÇ CSE471 • Anonim Chat • 2025"))
        menubar.add_cascade(label="Help", menu=helpmenu)

        self.root.config(menu=menubar)

    def ask_role(self):
        popup = tk.Toplevel(self.root)
        popup.title("Mod Seçimi")
        tk.Label(popup, text="Mod Seçiniz:").pack(pady=5)

        role_var = tk.StringVar(value="client")

        tk.Radiobutton(popup, text="Client", variable=role_var, value="client").pack(anchor=tk.W)
        tk.Radiobutton(popup, text="Gateway", variable=role_var, value="gateway").pack(anchor=tk.W)

        def submit_role():
            self.is_gateway = role_var.get() == "gateway"
            popup.destroy()
            if self.is_gateway:
                self.root.title("🔐 Anonim İnsanlar Chat 2025 [Gateway]")
                self.append_message("🟢 Gateway olarak giriş yaptınız.Hoşgeldiniz")
                self.load_gateway_list()
                self.append_message("📡 Aktif Gateway IP'leri:")
                for ip in self.gateway_list:
                    self.append_message(f"  • {ip}")
            else:
                self.root.title("🔐 Anonim İnsanlar Chat 2025 [Client]")
                self.append_message("🟢 Client olarak giriş yaptınız.Hoşgeldiniz")

        tk.Button(popup, text="Tamam", command=submit_role).pack(pady=5)

    def load_gateway_list(self):
        if os.path.exists(GATEWAY_LIST_PATH):
            with open(GATEWAY_LIST_PATH, "r") as f:
                self.gateway_list = [line.strip() for line in f if line.strip()]

    def append_message(self, msg):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, msg + "\n")
        self.chat_area.yview(tk.END)
        self.chat_area.config(state='disabled')

    def generate_keys(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open("my_private.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open("my_public.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        self.private_key = private_key
        self.append_message("✅ Anahtar çifti oluşturuldu.")

        self.filemenu.entryconfig("Connect to Network", state=tk.NORMAL)
        self.filemenu.entryconfig("Disconnect from Network", state=tk.NORMAL)

    def connect_to_network(self):
        if not self.private_key:
            messagebox.showwarning("Uyarı", "Önce anahtar üretmelisiniz!")
            return

        self.nickname = simpledialog.askstring("Kullanıcı Adı", "Lütfen kullanıcı adınızı girin:")
        if not self.nickname:
            return

        try:
            identity_packet = {
                "type": "identity",
                "nickname": self.nickname,
                "public_key": get_public_key_string(),
                "fake_ip": self.spoofed_ip
            }
            for _ in range(3):
                send_udp_broadcast(json.dumps(identity_packet).encode())
                time.sleep(0.1)
            self.user_map[self.my_ip] = (self.nickname, None)
            self.update_user_listbox()
            self.append_message(f"🔗 Ağa bağlanıldı: {self.nickname}")
        except Exception as e:
            self.append_message(f"❌ Anahtar yüklenemedi: {str(e)}")

    def disconnect_from_network(self):
        if not self.nickname:
            messagebox.showwarning("Uyarı", "Önce ağa bağlanmalısınız!")
            return

        quit_packet = {
            "type": "quit",
            "nickname": self.nickname
        }
        send_udp_broadcast(json.dumps(quit_packet).encode())
        self.append_message("🚪 Ağdan çıkış yapıldı.")
        if self.my_ip in self.user_map:
            del self.user_map[self.my_ip]
        self.nickname = None
        self.update_user_listbox()

    def update_user_listbox(self):
        self.user_listbox.delete(0, tk.END)
        for ip, (nickname, _) in self.user_map.items():
            label = f"{nickname} (Me)" if ip == self.my_ip else nickname
            self.user_listbox.insert(tk.END, label)

    def send_message(self):
        msg = self.entry.get()
        if msg == self.last_sent_msg:
            self.append_message("⚠️ Flood yapıyorsun: Aynı mesajı arka arkaya tekrar gönderemezsin.")
            return
        self.last_sent_msg = msg
        if not msg:
            return

        recipients = [(ip, pk) for ip, (nick, pk) in self.user_map.items() if pk is not None and ip != self.my_ip]

        if not recipients:
            self.append_message("⚠️ Hiçbir kullanıcı bulunamadı.")
            return

        raw_bytes = msg.encode()
        chunk_size = 190  # RSA 2048-bit OAEP sınırı

        chunks = [raw_bytes[i:i+chunk_size] for i in range(0, len(raw_bytes), chunk_size)]

        for ip, pubkey in recipients:
            try:
                msg_id = str(uuid.uuid4())
                total_parts = len(chunks)
                for i, chunk in enumerate(chunks):
                    encrypted = encrypt_message(chunk.decode(errors='ignore'), pubkey)
                    msg_packet = {
                        "type": "message",
                        "payload": encrypted.hex(),
                        "msg_id": msg_id,
                        "timestamp": time.time(),
                        "part": i,
                        "total_parts": total_parts,
                        "fake_ip": self.spoofed_ip
                    }
                    send_udp_broadcast(json.dumps(msg_packet).encode())
                    time.sleep(0.01)
            except Exception as e:
                print(f"[HATA] {ip} için şifreleme hatası: {e}")

        self.append_message(f"{self.nickname}: {msg}")
        self.entry.delete(0, tk.END)

    def start_udp_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('', PORT))
            print(f"[UDP-LISTENER] {PORT} portu dinleniyor...")

            while True:
                try:
                    data, addr = s.recvfrom(BUFFER_SIZE)
                    sender_ip = addr[0]
                    obj = json.loads(data.decode())
                    fake_ip = obj.get("fake_ip", sender_ip)
                    print(f"[RECV] Paket geldi {fake_ip} → {len(data)} byte")
                    print("[OBJ DEBUG]", obj)

                    if sender_ip == self.my_ip:
                        continue

                    if obj["type"] == "identity":
                        print(f"[DEBUG] Identity received from {fake_ip}: {obj.get('nickname')}")
                        try:
                            sender_pubkey = load_public_key_from_pem(obj["public_key"].encode())
                            self.user_map[sender_ip] = (obj["nickname"], sender_pubkey)
                            self.update_user_listbox()
                            self.append_message(f"🚨 [{obj['nickname']}] kimlik yayını yaptı.")
                        except Exception as e:
                            self.append_message(f"[HATA] Kimlik çözümleme hatası: {str(e)}")

                    elif obj["type"] == "message":
                        print(f"[DEBUG] Message received from {fake_ip}: {obj.get('msg_id')}")
                        msg_id = obj.get("msg_id")
                        timestamp = obj.get("timestamp", 0)
                        part = obj.get("part", 0)
                        total_parts = obj.get("total_parts", 1)
                        payload = bytes.fromhex(obj["payload"])

                        if msg_id not in self.msg_buffer:
                            self.msg_buffer[msg_id] = {}
                            self.msg_meta[msg_id] = (sender_ip, total_parts, timestamp)

                        self.msg_buffer[msg_id][part] = payload
                        print(f"[FRAGMENT] {msg_id} | part {part+1}/{total_parts}")

                        if len(self.msg_buffer[msg_id]) == total_parts:
                            full_encrypted = b''.join(self.msg_buffer[msg_id][i] for i in range(total_parts))
                            del self.msg_buffer[msg_id]
                            sender_ip, _, _ = self.msg_meta.pop(msg_id, (sender_ip, total_parts, timestamp))
                            if msg_id in self.seen_messages:
                                continue
                            now = time.time()
                            self.seen_messages = {
                                k: v for k, v in self.seen_messages.items() if now - v < 60
                            }
                            self.seen_messages[msg_id] = now
                            if self.is_gateway:
                                self.relay_to_gateways(data)
                            try:
                                plain = decrypt_message(full_encrypted, self.private_key)
                                sender_name = self.user_map.get(sender_ip, (sender_ip, None))[0]
                                self.append_message(f"{sender_name}: {plain}")
                            except Exception as e:
                                print(f"[DECRYPT ERROR] {e}")
                                self.append_message(f"[HATA] Şifre çözme hatası: {str(e)}")
                                return

                    # PRIVATE MESSAGE 
                    elif obj["type"] == "private_message":
                        print(f"[DEBUG] Private message received from {fake_ip}: {obj.get('msg_id')}")
                        if obj["target_ip"] != self.my_ip:
                            continue
                        try:
                            msg_id = obj.get("msg_id")
                            part = obj.get("part", 0)
                            total_parts = obj.get("total_parts", 1)
                            payload = bytes.fromhex(obj["payload"])
                            if msg_id not in self.private_msg_buffer:
                                self.private_msg_buffer[msg_id] = {}
                                self.private_msg_meta[msg_id] = (sender_ip, total_parts)
                            self.private_msg_buffer[msg_id][part] = payload
                            if len(self.private_msg_buffer[msg_id]) == total_parts:
                                full_encrypted = b''.join(self.private_msg_buffer[msg_id][i] for i in range(total_parts))
                                del self.private_msg_buffer[msg_id]
                                sender_ip, _ = self.private_msg_meta.pop(msg_id, (sender_ip, total_parts))
                                sender_name = obj.get("sender", fake_ip)
                                sender_pubkey = None
                                if sender_ip in self.user_map and self.user_map[sender_ip][1]:
                                    sender_pubkey = self.user_map[sender_ip][1]
                                key = (sender_ip, sender_name)
                                if key not in self.private_chats or not self.private_chats[key].window.winfo_exists():
                                    chat_win = PrivateChatWindow(self, sender_ip, sender_name, sender_pubkey, self.nickname)
                                    self.private_chats[key] = chat_win
                                try:
                                    plain = decrypt_message(full_encrypted, self.private_key)
                                    self.private_chats[key].append(f"{sender_name} (Özel): {plain}")
                                except Exception as e:
                                    print(f"[PRIVATE CHAT ERROR] {e}")
                        except Exception as e:
                            print(f"[PRIVATE CHAT ERROR] {e}")

                    # PRIVATE FILE
                    elif obj["type"] == "private_file":
                        print(f"[DEBUG] Private file received from {fake_ip}: {obj.get('msg_id')}")
                        if obj["target_ip"] != self.my_ip:
                            continue
                        try:
                            enc_payload = bytes.fromhex(obj["payload"])
                            file_b64 = decrypt_message(enc_payload, self.private_key)
                            file_bytes = base64.b64decode(file_b64)
                            file_name = obj.get("filename", f"received_{int(time.time())}")
                            save_path = filedialog.asksaveasfilename(title="Dosyayı Kaydet", initialfile=file_name)
                            if save_path:
                                with open(save_path, "wb") as f:
                                    f.write(file_bytes)
                                sender_name = obj.get("sender", fake_ip)
                                sender_pubkey = None
                                if sender_ip in self.user_map and self.user_map[sender_ip][1]:
                                    sender_pubkey = self.user_map[sender_ip][1]
                                key = (sender_ip, sender_name)
                                if key not in self.private_chats or not self.private_chats[key].window.winfo_exists():
                                    chat_win = PrivateChatWindow(self, sender_ip, sender_name, sender_pubkey, self.nickname)
                                    self.private_chats[key] = chat_win
                                self.private_chats[key].append(f"📥 Dosya alındı: {file_name}")
                        except Exception as e:
                            print(f"[PRIVATE FILE ERROR] {e}")

                    elif obj["type"] == "quit":
                        quitting_ip = sender_ip
                        if quitting_ip in self.user_map:
                            quitting_nick = self.user_map[quitting_ip][0]
                            del self.user_map[quitting_ip]
                            self.append_message(f"👋 {quitting_nick} ağdan ayrıldı.")
                            self.update_user_listbox()

                except Exception as e:
                    print(f"[UDP-LISTENER] Hata: {str(e)}")

    def relay_to_gateways(self, data: bytes):
        for ip in self.gateway_list:
            if ip == self.my_ip:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(data, (ip, PORT))
            except Exception as e:
                print(f"[RELAY HATA] {ip} → {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.mainloop()
