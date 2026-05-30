import paramiko
import os
from pathlib import Path


def deploy():
    vps_host = "207.2.122.94"
    vps_user = "capstone"
    ssh_key_path = "C:/Users/user/.ssh/id_ed25519"

    local_model = Path("models/trained_models/modsec_xgb.pkl")
    remote_dir = "/home/capstone/ojs_git/docker-ojs/inference"
    remote_model = f"{remote_dir}/model.pkl"

    try:
        print(f"Connecting to {vps_user}@{vps_host}...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(vps_host, username=vps_user, key_filename=ssh_key_path)
        print("Connected!")

        sftp = ssh.open_sftp()
        
        # 1. Pastikan folder tujuan ada
        try:
            sftp.chdir(remote_dir)
        except IOError:
            print(f"Folder {remote_dir} belum ada, membuat folder...")
            ssh.exec_command(f"mkdir -p {remote_dir}")
            sftp.chdir(remote_dir)

        # 2. Cek apakah model lama sudah ada untuk di-arsip
        try:
            sftp.stat("model.pkl")
            # Cari nomor versi v1, v2, dst
            files = sftp.listdir(".")
            version_count = len([f for f in files if f.startswith("model_v") and f.endswith(".pkl")])
            next_version = f"model_v{version_count + 1}.pkl"
            
            print(f"[INFO] Mengarsipkan model lama ke: {next_version}")
            sftp.rename("model.pkl", next_version)
        except FileNotFoundError:
            print("[INFO] Tidak ada model lama, melewati proses arsip.")

        # 3. Upload model baru
        print(f"Uploading {local_model.name} to {remote_model}...")
        sftp.put(str(local_model), "model.pkl")
        sftp.close()
        
        print("Done! Model berhasil dideploy dan versi lama diarsipkan.")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'ssh' in locals() and ssh:
            ssh.close()

if __name__ == "__main__":
    deploy()
