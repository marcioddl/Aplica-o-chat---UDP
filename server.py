import socket
import zlib
import json

# CONFIGURAÇÕES
SERVER_IP = "127.0.0.1"
SERVER_PORT = 9000

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_IP, SERVER_PORT))

# Estado: Clientes e Controle de Logs
clientes = {} 
ultimo_pacote = {} # Para não repetir o print do JSON (Deduplicação Visual)

def normalize(name: str) -> str:
    return name.strip().lower()

def compute_checksum_dict(d: dict) -> int:
    if 'checksum' in d:
        d = {k: v for k, v in d.items() if k != 'checksum'}
    s = json.dumps(d, sort_keys=True, ensure_ascii=False).encode()
    return zlib.crc32(s) & 0xffffffff

def make_packet(obj: dict) -> bytes:
    obj['checksum'] = compute_checksum_dict(obj)
    return json.dumps(obj, ensure_ascii=False).encode()

def parse_packet(data: bytes) -> dict:
    try:
        return json.loads(data.decode(errors="ignore"))
    except:
        return None

print(f"--- SERVIDOR RUDP (JSON) RODANDO EM {SERVER_IP}:{SERVER_PORT} ---")
print("Aguardando conexões e pacotes...")

try:
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            obj = parse_packet(data)
            
            if obj is None or 'type' not in obj:
                print(f"[LIXO] Recebido dados inválidos de {addr}")
                continue

            # logica dos logs repetidos
            # Verifica se é exatamente o mesmo pacote de antes 
            current_checksum = obj.get('checksum')
            is_duplicate = False
            
            if addr in ultimo_pacote:
                last_chk, count = ultimo_pacote[addr]
                if last_chk == current_checksum:
                    is_duplicate = True
                    count += 1
                    ultimo_pacote[addr] = (current_checksum, count)
                    # IMPRIME SÓ O RESUMO
                    print(f"   └── [RETRANSMISSÃO DETECTADA] Pacote repetido de {addr} (Tentativa {count}). Ocultando JSON.")
                else:
                    # Pacote novo desse endereço
                    ultimo_pacote[addr] = (current_checksum, 1)
            else:
                # Primeiro pacote desse endereço
                ultimo_pacote[addr] = (current_checksum, 1)

            # Se NÃO for duplicata, imprime o JSON completo
            if not is_duplicate:
                print(f"\n{'='*10} NOVO PACOTE DE {addr} {'='*10}")
                print(json.dumps(obj, indent=4, ensure_ascii=False))
                print("-" * 60)
            

            t = obj['type']

            # CHECAGEM DE ERRO DE INTEGRIDADE 
            chk_recv = obj.get("checksum")
            chk_calc = compute_checksum_dict(obj)
            
            if chk_recv is None or chk_calc != chk_recv:
                print(f"❌ [ERRO DE INTEGRIDADE] Checksum falhou!")
                print(f"   Esperado: {chk_calc} | Recebido: {chk_recv}")
                print("   -> O pacote foi descartado pelo servidor.")
                continue # Pula o processamento obrigando o cliente a reenviar

            # PROCESSAMENTO 

            # 1. LOGIN
            if t == "LOGIN":
                name = obj.get("name", "").strip()
                if name:
                    nkey = normalize(name)
                    clientes[nkey] = (name, addr)
                    print(f"[CONEXÃO] Usuário '{name}' registrado.")
                    sock.sendto(make_packet({"type": "LOGIN_OK", "msg": f"Bem-vindo, {name}!"}), addr)
                continue

            # 2. LISTA
            if t == "LIST":
                lista = [v[0] for v in clientes.values()]
                msg_lista = ", ".join(lista) if lista else "Ninguém online"
                sock.sendto(make_packet({"type": "LIST_RESP", "clients": msg_lista}), addr)
                continue

            # 3. mensagen de dados delay
            if t == "DATA":
                dest_name = obj.get("dest", "")
                dest_key = normalize(dest_name)
                
                if dest_key in clientes:
                    target_name, target_addr = clientes[dest_key]
                    relay_pkt = {
                        "type": "RELAY",
                        "from": obj.get("from"), 
                        "seq": obj.get("seq"),
                        "payload": obj.get("payload")
                    }
                    sock.sendto(make_packet(relay_pkt), target_addr)
                    print(f"[ENCAMINHAMENTO] Msg de '{obj.get('from')}' -> '{target_name}' (Seq {obj.get('seq')})")
                else:
                    sock.sendto(make_packet({"type": "ERROR", "msg": f"Usuário {dest_name} não encontrado."}), addr)
                    print(f"[ERRO LÓGICO] Tentativa de envio para usuário inexistente: '{dest_name}'")
                continue

            # 4. confirmaçao ack
            if t == "ACK":
                to_name = obj.get("to", "")
                to_key = normalize(to_name)
                
                if to_key in clientes:
                    target_name, target_addr = clientes[to_key]
                    ack_fwd = {
                        "type": "ACK_FORWARD",
                        "from": obj.get("from"),
                        "seq": obj.get("seq")
                    }
                    sock.sendto(make_packet(ack_fwd), target_addr)
                    print(f"[ACK REPASSADO] De '{obj.get('from')}' -> '{target_name}' (Ref. Seq {obj.get('seq')})")
                continue

            if t == "LOGOUT":
                pass

        except Exception as e:
            print(f"Erro no loop do servidor: {e}")

except KeyboardInterrupt:
    print("\nServidor encerrado.")
finally:
    sock.close()