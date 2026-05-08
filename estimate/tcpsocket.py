import socket
import time

HOST = '100.101.142.68'  # IP Lanforge
PORT = 22022

def send_lua_cmd(cmd):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            # Lua yêu cầu dấu ; ở cuối và \n để thực thi
            full_cmd = f"{cmd}\n"
            s.sendall(full_cmd.encode())
            print(f"Executed: {cmd}")
    except Exception as e:
        print(f"Error: {e}")

# Kịch bản test: Set rate 5% và Start
send_lua_cmd('pktgen.set("0", "rate", 5);')
time.sleep(0.5) 
send_lua_cmd('pktgen.start("0");')
time.sleep(120)
send_lua_cmd('pktgen.stop("0");')
