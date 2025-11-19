import socket
import threading
import time
import zlib
import json
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk

SERVER_IP = "127.0.0.1"
SERVER_PORT = 9000
TIMEOUT = 3.0     
MAX_RETRIES = 5     #

class RUDPClientGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("RUDP Chat (Protocolo Confiável)")
        self.master.geometry("900x650")
        
        self.my_name = ""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # CONTROLE DO PROTOCOLO
        self.ack_events = {}    # aguardar ack
        self.ack_results = {}   # resultado do ACK tru or false
        self.seq_counters = {}  # contador sequência de envio
        self.peer_last_seq = {} # deduplicação: ultimo seq recebido de cada usuário

        self.running = True
        self.conversations = {} 
        self.current_chat_partner = None 

        # interface
        style = ttk.Style()
        style.configure("TNotebook", tabposition='n') 

        # tela login
        frame_conn = tk.Frame(master, bg="#f0f0f0", bd=1, relief=tk.RAISED)
        frame_conn.pack(pady=5, fill=tk.X, padx=5)
        
        tk.Label(frame_conn, text="Seu Nome:", bg="#f0f0f0").pack(side=tk.LEFT, padx=5, pady=5)
        self.ent_name = tk.Entry(frame_conn, font=("Arial", 11))
        self.ent_name.pack(side=tk.LEFT, padx=5)
        self.btn_login = tk.Button(frame_conn, text="Entrar", command=self.do_login, bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
        self.btn_login.pack(side=tk.LEFT, padx=5)

        # principal
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

        # chat
        self.tab_chat = tk.Frame(self.notebook)
        self.notebook.add(self.tab_chat, text="   💬 Mensagens   ")

        paned = tk.PanedWindow(self.tab_chat, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        paned.pack(fill=tk.BOTH, expand=True)

        # Lista de Usuários
        frame_left = tk.Frame(paned, width=200, bg="#e0e0e0")
        paned.add(frame_left)
        tk.Label(frame_left, text="Usuários Online", bg="#e0e0e0", font=("Arial", 10, "bold")).pack(pady=5)
        self.btn_refresh = tk.Button(frame_left, text="🔄 Atualizar", command=self.request_list, state=tk.DISABLED)
        self.btn_refresh.pack(pady=2, padx=5, fill=tk.X)
        self.list_users = tk.Listbox(frame_left, font=("Arial", 11), selectmode=tk.SINGLE, bg="white")
        self.list_users.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
        self.list_users.bind('<<ListboxSelect>>', self.on_select_user)

        # Conversa 
        frame_right = tk.Frame(paned, bg="white")
        paned.add(frame_right)
        self.lbl_talking_to = tk.Label(frame_right, text="Selecione um contato...", bg="#eee", font=("Arial", 11, "bold"), anchor="w", padx=10, pady=5)
        self.lbl_talking_to.pack(fill=tk.X)
        self.chat_area = scrolledtext.ScrolledText(frame_right, state='disabled', font=("Segoe UI Emoji", 11))
        self.chat_area.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
        self.chat_area.tag_config('me', foreground='white', background='#0078FF', justify='right', lmargin1=150, lmargin2=150, rmargin=10, spacing1=5, spacing3=5)
        self.chat_area.tag_config('other', foreground='black', background='#E5E5EA', justify='left', lmargin1=10, lmargin2=10, rmargin=150, spacing1=5, spacing3=5)
        self.chat_area.tag_config('sys', foreground='gray', justify='center', font=("Arial", 8))

        frame_send = tk.Frame(frame_right, bg="#f0f0f0", height=50)
        frame_send.pack(fill=tk.X, padx=5, pady=5)
        self.ent_msg = tk.Entry(frame_send, font=("Arial", 11))
        self.ent_msg.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5, ipady=5)
        self.ent_msg.bind("<Return>", self.on_send_click)
        self.btn_send = tk.Button(frame_send, text="ENVIAR ➤", command=self.on_send_click, state=tk.DISABLED, bg="#2196F3", fg="white", font=("Arial", 10, "bold"))
        self.btn_send.pack(side=tk.LEFT, padx=5)

        # logs e testes
        self.tab_logs = tk.Frame(self.notebook)
        self.notebook.add(self.tab_logs, text="   🛠️ Debug & Testes   ")
        
        frame_logs_content = tk.Frame(self.tab_logs)
        frame_logs_content.pack(expand=True, fill=tk.BOTH)
        self.log_area = scrolledtext.ScrolledText(frame_logs_content, state='disabled', width=60, bg="black", fg="#00FF00", font=("Consolas", 9))
        self.log_area.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        #  PAINEL DE SIMULAÇÃO (REQ. DO PROFESSOR)
        frame_sim = tk.Frame(frame_logs_content, width=220, bg="#e0e0e0")
        frame_sim.pack(side=tk.RIGHT, fill=tk.Y)
        
        tk.Label(frame_sim, text="Opções de Teste", bg="#e0e0e0", font=("Arial", 11, "bold")).pack(pady=10)
        
        # 1. retransmissão por Erro
        self.var_corrupt = tk.BooleanVar()
        tk.Checkbutton(frame_sim, text="Simular Erro (Bit Flip)", variable=self.var_corrupt, bg="#e0e0e0", justify="left").pack(anchor='w', padx=10, pady=5)
        
        # 2. retransmissão por Estouro de Tempo 
        self.var_drop_in = tk.BooleanVar()
        tk.Checkbutton(frame_sim, text="Simular Perda de Pacote", variable=self.var_drop_in, bg="#e0e0e0", justify="left").pack(anchor='w', padx=10, pady=5)
        
        # 3. Retransmissão por Descarte de Confirmação (ACK)
        self.var_drop_ack = tk.BooleanVar()
        tk.Checkbutton(frame_sim, text="Simular Perda de ACK", variable=self.var_drop_ack, bg="#e0e0e0", justify="left").pack(anchor='w', padx=10, pady=5)

    # logica interface
    def on_select_user(self, event):
        selection = self.list_users.curselection()
        if not selection: return
        partner_name = self.list_users.get(selection[0])
        if partner_name == self.my_name: return
        self.current_chat_partner = partner_name
        self.lbl_talking_to.config(text=f"Conversando com: {partner_name}", bg="#b3e5fc")
        self.btn_send.config(state=tk.NORMAL)
        self.load_history(partner_name)

    def load_history(self, partner_name):
        self.chat_area.config(state='normal')
        self.chat_area.delete(1.0, tk.END)
        history = self.conversations.get(partner_name, [])
        for item in history:
            if item['type'] == 'sys':
                self.chat_area.insert(tk.END, f"--- {item['msg']} ---\n", 'sys')
            else:
                tag = 'me' if item['is_me'] else 'other'
                self.chat_area.insert(tk.END, f" {item['msg']} \n", tag)
                self.chat_area.insert(tk.END, "\n", tag)
        self.chat_area.see(tk.END)
        self.chat_area.config(state='disabled')

    def save_and_show_message(self, partner, msg, is_me=False, is_sys=False):
        if partner not in self.conversations: self.conversations[partner] = []
        msg_obj = {'msg': msg, 'is_me': is_me, 'type': 'sys' if is_sys else 'msg'}
        self.conversations[partner].append(msg_obj)
        if self.current_chat_partner == partner:
            self.chat_area.config(state='normal')
            if is_sys:
                self.chat_area.insert(tk.END, f"--- {msg} ---\n", 'sys')
            else:
                tag = 'me' if is_me else 'other'
                self.chat_area.insert(tk.END, f" {msg} \n", tag)
                self.chat_area.insert(tk.END, "\n", tag)
            self.chat_area.see(tk.END)
            self.chat_area.config(state='disabled')

    # THREAD DE RECEBIMENTO - CRE DO PROTOCOLO
    def receiver_thread(self):
        self.sock.settimeout(None)
        while self.running:
            try:
                data, _ = self.sock.recvfrom(4096)
                pkt = self.parse_packet(data)
                if pkt is None: continue
                
                t = pkt.get("type")

                # REQUISITO 2: Retransmissão por estouro de tempo (Descartar pacotes recebidos)
                if self.var_drop_in.get() and t in ["RELAY", "ACK_FORWARD"]:
                    self.log_debug(f">>> SIMULAÇÃO: Pacote recebido ignorado (Drop Packet ativado).")
                    continue 

                if t == "LOGIN_OK":
                    self.log_debug(f"SERVER: {pkt.get('msg')}")
                    self.request_list()
                    continue
                if t == "ERROR":
                    self.log_debug(f"ERRO SERVER: {pkt.get('msg')}")
                    continue
                if t == "LIST_RESP":
                    clients_str = pkt.get("clients", "")
                    self.master.after(0, lambda c=clients_str: self.update_list_ui(c))
                    continue

                # REQUISITO 1 : Verifica Checksum
                # Se o "Bit Flip" foi ativado no remetente, o CRC falha aqui.
                if t == "RELAY":
                    chk_recv = pkt.get("checksum")
                    if chk_recv is None or self.compute_checksum_dict(pkt) != chk_recv:
                        self.log_debug(">>> ERRO CRC: Pacote corrompido recebido. Descartando (vai dar timeout no sender).")
                        continue
                    
                    sender = pkt.get("from")
                    seq = pkt.get("seq")
                    payload = pkt.get("payload")

                    # Lógica de Deduplicação (Evita mostrar msg repetida se o ACK se perdeu)
                    last_seq = self.peer_last_seq.get(sender, -1)
                    if seq == last_seq:
                        self.log_debug(f"DUPLICATA: Mensagem {seq} já recebida. Reenviando apenas o ACK.")
                        if not self.var_drop_ack.get():
                            ack = {"type": "ACK", "to": sender, "from": self.my_name, "seq": seq}
                            self.sock.sendto(self.make_packet(ack), (SERVER_IP, SERVER_PORT))
                        continue
                    
                    # Processa nova mensagem
                    self.peer_last_seq[sender] = seq
                    self.log_debug(f"MENSAGEM RECEBIDA de {sender}: {payload} (Seq {seq})")
                    
                    # REQUISITO 3: Retransmissão por descarte de confirmações
                    if self.var_drop_ack.get():
                        self.log_debug(">>> SIMULAÇÃO: Mensagem processada, mas ACK descartado.")
                        # Não envia o ACK. O remetente vai reenviar.
                    else:
                        ack = {"type": "ACK", "to": sender, "from": self.my_name, "seq": seq}
                        self.sock.sendto(self.make_packet(ack), (SERVER_IP, SERVER_PORT))
                        self.log_debug(f"ACK enviado para {sender} (Seq {seq})")

                    self.master.after(0, lambda s=sender, p=payload: self.save_and_show_message(s, p, is_me=False))
                    continue

                if t == "ACK_FORWARD":
                    seq = pkt.get("seq")
                    frm = pkt.get("from")
                    key = (frm.strip().lower(), seq)
                    if key in self.ack_events:
                        self.ack_results[key] = True 
                        self.ack_events[key].set()   
                        self.log_debug(f"ACK confirmado de {frm} (Seq {seq})")
                    continue

            except OSError: break
            except Exception as e: self.log_debug(f"Erro Receiver: {e}")

    # envio
    def on_send_click(self, event=None):
        if not self.current_chat_partner:
            messagebox.showwarning("Aviso", "Selecione um usuário!")
            return
        msg = self.ent_msg.get().strip()
        if not msg: return
        dest = self.current_chat_partner
        self.ent_msg.delete(0, tk.END)
        threading.Thread(target=self.send_reliable_logic, args=(dest, msg)).start()

    def send_reliable_logic(self, dest, message):
        dest_norm = dest.strip().lower()
        seq = self.seq_counters.get(dest_norm, 0) + 1
        self.seq_counters[dest_norm] = seq
        
        key = (dest_norm, seq)
        ev = threading.Event()
        self.ack_events[key] = ev
        self.ack_results[key] = False

        pkt = {"type": "DATA", "from": self.my_name, "dest": dest, "seq": seq, "payload": message}
        data_bytes = self.make_packet(pkt)

        # REQUISITO 1  Alterar informação após calcular checksum
        if self.var_corrupt.get():
            b = bytearray(data_bytes)
            if len(b) > 0: b[min(10, len(b)-1)] ^= 0xFF # Inverte bits
            data_bytes = bytes(b)
            self.log_debug(f">>> SIMULAÇÃO: Enviando pacote CORROMPIDO (Seq {seq})")
        
        attempts = 0
        success = False
        
        while attempts < MAX_RETRIES:
            attempts += 1
            self.log_debug(f"Enviando para {dest} (Seq {seq}) - Tentativa {attempts}...")
            try: self.sock.sendto(data_bytes, (SERVER_IP, SERVER_PORT))
            except: pass

            # Aguarda ACK
            if ev.wait(timeout=TIMEOUT):
                if self.ack_results.get(key):
                    success = True
                    self.log_debug(f"Sucesso: Entregue a {dest} (Seq {seq})")
                    self.master.after(0, lambda: self.save_and_show_message(dest, message, is_me=True))
                    break
            else:
                self.log_debug(f"TIMEOUT! Sem ACK de {dest} para Seq {seq}. Retransmitindo...")
        
        if not success:
            self.log_debug(f"FALHA FATAL: Desistindo de enviar para {dest} após {MAX_RETRIES} tentativas.")
            self.master.after(0, lambda: messagebox.showerror("Falha", f"Erro de rede ao enviar para {dest}."))
        
        if key in self.ack_events: del self.ack_events[key]
        if key in self.ack_results: del self.ack_results[key]

    # utilitarios
    def log_debug(self, text):
        timestamp = time.strftime("%H:%M:%S")
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, f"[{timestamp}] {text}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')

    def compute_checksum_dict(self, d):
        if 'checksum' in d: d = {k: v for k, v in d.items() if k != 'checksum'}
        s = json.dumps(d, sort_keys=True, ensure_ascii=False).encode()
        return zlib.crc32(s) & 0xffffffff

    def make_packet(self, obj):
        obj['checksum'] = self.compute_checksum_dict(obj)
        return json.dumps(obj, ensure_ascii=False).encode()

    def parse_packet(self, data):
        try: return json.loads(data.decode(errors="ignore"))
        except: return None

    def do_login(self):
        name = self.ent_name.get().strip()
        if not name: return
        self.my_name = name
        try:
            self.sock.sendto(self.make_packet({"type": "LOGIN", "name": name}), (SERVER_IP, SERVER_PORT))
            self.btn_login.config(state=tk.DISABLED)
            self.ent_name.config(state=tk.DISABLED)
            self.btn_refresh.config(state=tk.NORMAL)
            threading.Thread(target=self.receiver_thread, daemon=True).start()
            self.log_debug(f"Login enviado: {name}")
        except Exception as e: self.log_debug(f"Erro: {e}")

    def request_list(self):
        try: self.sock.sendto(self.make_packet({"type": "LIST"}), (SERVER_IP, SERVER_PORT))
        except: pass

    def update_list_ui(self, clients_str):
        self.list_users.delete(0, tk.END)
        for u in [x.strip() for x in clients_str.split(",") if x.strip()]:
            if u != self.my_name: self.list_users.insert(tk.END, u)

if __name__ == "__main__":
    root = tk.Tk()
    app = RUDPClientGUI(root)
    root.mainloop()