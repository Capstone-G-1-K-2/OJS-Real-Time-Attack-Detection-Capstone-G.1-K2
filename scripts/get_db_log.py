import pandas as pd
import psycopg2
from sshtunnel import SSHTunnelForwarder
from pathlib import Path

# --- KONFIGURASI SSH (VPS) ---
SSH_HOST = "207.2.122.94"
SSH_USER = "root"
SSH_KEY = "C:/Users/user/.ssh/id_ed25519" # Path ke private key kamu

# --- KONFIGURASI DATABASE (POSTGRES) ---
DB_NAME = "modsec_db"      # Ganti dengan nama database kamu
DB_USER = "postgres"       # Ganti dengan user postgres kamu
DB_PASS = "password_kamu"  # Ganti dengan password postgres kamu
DB_HOST = "127.0.0.1"      # Tetap 127.0.0.1 karena kita pakai Tunnel

def fetch_data():
    # 1. Buat SSH Tunnel
    with SSHTunnelForwarder(
        (SSH_HOST, 22),
        ssh_username=SSH_USER,
        ssh_pkey=SSH_KEY,
        remote_bind_address=('127.0.0.1', 5432) # Port Postgres di VPS
    ) as tunnel:
        
        print(f"[INFO] SSH Tunnel berhasil dibuka di port: {tunnel.local_bind_port}")
        
        # 2. Koneksi ke Database melalui Port Tunnel
        try:
            conn = psycopg2.connect(
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASS,
                host='127.0.0.1',
                port=tunnel.local_bind_port # Gunakan port dinamis dari tunnel
            )
            
            print("[INFO] Berhasil terhubung ke Database PostgreSQL!")
            
            # 3. Ambil data pakai Pandas
            query = "SELECT * FROM attack_logs" # Ganti dengan nama tabelmu
            df = pd.read_sql_query(query, conn)
            
            # 4. Simpan ke CSV lokal
            output_path = Path("data/dataset/fetched_logs_vps.csv")
            output_path.parent.mkdir(parents=True, exist_ok=True)
            df.to_csv(output_path, index=False)
            
            print(f"[SUCCESS] Data berhasil ditarik! Total: {len(df)} baris.")
            print(f"File disimpan di: {output_path}")
            
            conn.close()
            
        except Exception as e:
            print(f"[ERROR] Gagal akses database: {e}")

if __name__ == "__main__":
    fetch_data()
