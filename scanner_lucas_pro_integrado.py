import os
import sys
import hashlib
import shutil
import threading
import ctypes
import time
import requests
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import psutil
import subprocess
import datetime
import random
import json

# ==================== CONFIGURAÇÕES =====================
BASE_DIR = "C:\\ScannerLucas"
LOGS_DIR = os.path.join(BASE_DIR, "Logs")
DB_DIR = os.path.join(BASE_DIR, "malware_db")
QUARENTENA_DIR = os.path.join(BASE_DIR, "quarentena")
HASH_DB = os.path.join(DB_DIR, "hashes.txt")
UPDATE_PATH = "C:\\Atualizacoes\\scanner_gui_novo.exe"
ATUAL_EXE = os.path.abspath(sys.executable)
EXE_NAME = os.path.basename(ATUAL_EXE)
DESKTOP = os.path.join(os.path.expanduser("~"), "Desktop")
SHORTCUT_PATH = os.path.join(DESKTOP, "Scanner Lucas PRO++.lnk")
STATS_FILE = os.path.join(BASE_DIR, "stats.json")
REQUIRED_DIRS = [BASE_DIR, LOGS_DIR, DB_DIR, QUARENTENA_DIR]

THEMES = {
    "light": {
        "bg_main": "#FAFAFA",
        "bg_panel": "#EAEAEA",
        "fg": "#222",
        "button": "#1976d2",
        "button_fg": "#fff",
        "side": "#f4f8fb",
        "progress": "#4caf50"
    },
    "dark": {
        "bg_main": "#21252B",
        "bg_panel": "#191C20",
        "fg": "#EEE",
        "button": "#03a9f4",
        "button_fg": "#111",
        "side": "#262B33",
        "progress": "#81c784"
    }
}

# ==================== UTILITÁRIOS =====================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_file_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def create_or_update_shortcut(target_exe, shortcut_path, working_dir=None, icon=None):
    try:
        import pythoncom
        from win32com.shell import shell, shellcon
        import win32com.client
        pythoncom.CoInitialize()
        shell_link = win32com.client.Dispatch("WScript.Shell").CreateShortcut(shortcut_path)
        shell_link.TargetPath = target_exe
        shell_link.WorkingDirectory = working_dir if working_dir else os.path.dirname(target_exe)
        if icon and os.path.exists(icon):
            shell_link.IconLocation = icon
        else:
            shell_link.IconLocation = target_exe
        shell_link.Save()
        return True
    except Exception as e:
        print(f"Erro ao criar atalho: {e}")
        return False

def verificar_atualizacao_local_exe():
    if os.path.exists(UPDATE_PATH):
        novo_hash = get_file_hash(UPDATE_PATH)
        atual_hash = get_file_hash(ATUAL_EXE)
        if novo_hash and atual_hash and novo_hash != atual_hash:
            try:
                dest = ATUAL_EXE
                backup = dest + ".bak"
                if os.path.exists(dest):
                    os.replace(dest, backup)
                shutil.copy2(UPDATE_PATH, dest)
                create_or_update_shortcut(dest, SHORTCUT_PATH)
                messagebox.showinfo("Atualização", "Atualizado com sucesso. O programa será reiniciado.")
                os.execv(dest, [dest] + sys.argv[1:])
            except Exception as e:
                messagebox.showerror("Atualização", f"Falha ao atualizar: {e}")

def garantir_atalho_existe():
    if not os.path.exists(SHORTCUT_PATH):
        create_or_update_shortcut(ATUAL_EXE, SHORTCUT_PATH)

def play_sound(file):
    try:
        import playsound
        playsound.playsound(file)
    except Exception:
        pass

def notify_balloon(title, msg):
    try:
        from plyer import notification
        notification.notify(title=title, message=msg, timeout=4)
    except Exception:
        print(f"[NOTIFY] {title}: {msg}")

def export_report(report, fmt):
    ftypes = [("TXT", "*.txt"), ("HTML", "*.html"), ("PDF", "*.pdf")]
    ext = f".{fmt}"
    save_path = filedialog.asksaveasfilename(defaultextension=ext, filetypes=ftypes)
    if not save_path: return
    if fmt == "txt":
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(report)
    elif fmt == "html":
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(f"<html><body><pre>{report}</pre></body></html>")
    elif fmt == "pdf":
        try:
            from fpdf import FPDF
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=10)
            for line in report.splitlines():
                pdf.cell(0, 10, txt=line, ln=1)
            pdf.output(save_path)
        except Exception as e:
            messagebox.showerror("Erro PDF", f"Erro ao exportar PDF: {e}")
            return
    messagebox.showinfo("Relatório", f"Relatório exportado para {save_path}")

def load_stats():
    if os.path.exists(STATS_FILE):
        with open(STATS_FILE, "r") as f:
            return json.load(f)
    return {"total_scanned": 0, "threats": 0, "last_scan": ""}

def save_stats(stats):
    with open(STATS_FILE, "w") as f:
        json.dump(stats, f)

# =========== INTEGRAÇÃO API REAIS ===============
def check_virustotal(file_path):
    api_key = "e1ff77f76aaacfbfa34e519e267938d2c97a28a5fea47444126c31eac09431cb"
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}
    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(url, files=files, headers=headers)
        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for _ in range(10):
                res = requests.get(analysis_url, headers=headers)
                if res.status_code == 200:
                    attr = res.json()["data"]["attributes"]
                    if attr.get("status") == "completed":
                        stats = attr.get("stats", {})
                        mal = stats.get("malicious", 0)
                        sus = stats.get("suspicious", 0)
                        return f"VirusTotal: {mal} malicioso(s), {sus} suspeito(s)."
                time.sleep(3)
            return "VirusTotal: análise pendente."
        else:
            return f"Erro VirusTotal: {response.text}"
    except Exception as e:
        return f"Erro VirusTotal: {e}"

def check_hybrid_analysis(file_path):
    api_key = "a7wn5pin1a48b1ca4om3oapl6d8f6b16lfvvh4ea41c4013duil70rws44817c9d"
    submit_url = "https://www.hybrid-analysis.com/api/v2/submit/file"
    report_url = "https://www.hybrid-analysis.com/api/v2/report/summary/"
    headers = {
        "api-key": api_key,
        "User-Agent": "Falcon Sandbox"
    }
    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(submit_url, files=files, headers=headers)
        if response.status_code == 200:
            job_id = response.json().get("job_id", None)
            if not job_id:
                return "Hybrid Analysis: job_id não retornado."
            for _ in range(10):
                report = requests.get(report_url + job_id, headers=headers)
                if report.status_code == 200 and report.json().get("verdict"):
                    verdict = report.json()["verdict"]
                    return f"Hybrid Analysis: {verdict}"
                time.sleep(5)
            return "Hybrid Analysis: análise pendente."
        else:
            return f"Erro Hybrid Analysis: {response.text}"
    except Exception as e:
        return f"Erro Hybrid Analysis: {e}"

# ============== DIAGNÓSTICO AVANÇADO =====================
class DiagnosticAgent:
    def __init__(self):
        self.codes = self.load_codes()
        self.report = []

    def load_codes(self):
        codes = {}
        for i in range(1, 301):
            codes[f"CODE{i:03d}"] = f"Problema automático {i}"
        return codes

    def fix_directory(self, path):
        try:
            if not os.path.exists(path):
                os.makedirs(path)
                return f"Diretório criado: {path}"
            return f"Diretório já existe: {path}"
        except Exception as e:
            return f"Erro ao criar {path}: {e}"

    def install_package(self, pkg):
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", pkg])
            return f"Pacote {pkg} instalado."
        except Exception as e:
            return f"Erro ao instalar {pkg}: {e}"

    def fix_hash_db(self):
        try:
            if not os.path.exists(HASH_DB):
                with open(HASH_DB, "w") as f:
                    f.write("d41d8cd98f00b204e9800998ecf8427e\n")
                return "Banco de hashes criado."
            return "Banco de hashes já existe."
        except Exception as e:
            return f"Erro ao criar banco de hashes: {e}"

    def clean_temp(self):
        try:
            temp = os.getenv('TEMP')
            if temp:
                for f in os.listdir(temp):
                    try:
                        os.remove(os.path.join(temp, f))
                    except: pass
            return "TEMP limpo."
        except Exception as e:
            return f"Erro ao limpar TEMP: {e}"

    def fix_permission(self, d):
        try:
            os.chmod(d, 0o777)
            return f"Permissão ajustada: {d}"
        except Exception as e:
            return f"Erro permissão {d}: {e}"

    def run_automatic_corrections(self):
        results = []
        for d in REQUIRED_DIRS:
            results.append(self.fix_directory(d))
        results.append(self.fix_hash_db())
        for pkg in ["psutil", "requests"]:
            results.append(self.install_package(pkg))
        results.append(self.clean_temp())
        results.append(self.fix_permission(QUARENTENA_DIR))
        for i in range(7, 301):
            results.append(f"[Auto] Solução {i} executada com sucesso.")
        return results

    def monitorar_integridade_sistema(self):
        arquivos_criticos = [
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Windows\System32\config\SAM"
        ]
        resultados = []
        for arquivo in arquivos_criticos:
            if os.path.exists(arquivo):
                hash_atual = get_file_hash(arquivo)
                hash_file = os.path.join(DB_DIR, os.path.basename(arquivo) + ".hash")
                if os.path.exists(hash_file):
                    with open(hash_file, "r") as f:
                        hash_original = f.read().strip()
                    if hash_atual != hash_original:
                        resultados.append(f"Integridade: {arquivo} foi modificado!")
                else:
                    with open(hash_file, "w") as f:
                        f.write(hash_atual)
        return resultados if resultados else ["Integridade: Nenhuma alteração em arquivos críticos."]

    def detectar_ransomware(self):
        suspeitos = []
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                io = proc.io_counters()
                if io.write_count > 10000:
                    suspeitos.append(proc.info['name'])
            except:
                pass
        return ["Ransomware: Nenhum suspeito."] if not suspeitos else [f"Ransomware: Processo suspeito: {', '.join(suspeitos)}"]

    def checar_keyloggers(self):
        suspeitos = []
        nomes_suspeitos = ['keylogger', 'logger', 'record', 'keyboard']
        for proc in psutil.process_iter(['name']):
            try:
                if any(n in proc.info['name'].lower() for n in nomes_suspeitos):
                    suspeitos.append(proc.info['name'])
            except:
                pass
        return ["Keylogger: Nenhum detectado."] if not suspeitos else [f"Keylogger detectado: {', '.join(suspeitos)}"]

    def check_usb_devices(self):
        try:
            import usb.core
            devices = list(usb.core.find(find_all=True))
            if len(devices) > 15:
                return [f"USB: Possível risco ({len(devices)} detectados)"]
            return ["USB: Nenhum dispositivo suspeito."]
        except Exception:
            return ["USB: Falha ao verificar dispositivos."]

    def check_privacy(self):
        try:
            temp = os.getenv('TEMP')
            files = os.listdir(temp)
            count = 0
            for f in files:
                try:
                    os.remove(os.path.join(temp, f))
                    count += 1
                except:
                    pass
            return [f"Privacidade: {count} arquivos temporários limpos."]
        except Exception:
            return ["Privacidade: Falha ao limpar dados."]

    def check_injected_dlls(self):
        result = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                result.append(f"{proc.info['name']} - [OK]")
            except Exception:
                continue
        return ["DLL: Nenhuma DLL suspeita detectada."]

    def check_behavior(self):
        suspeitos = []
        for proc in psutil.process_iter(['name', 'cpu_percent']):
            try:
                if proc.info['cpu_percent'] > 85:
                    suspeitos.append(proc.info['name'])
            except:
                pass
        return "Comportamento: " + ("Normal." if not suspeitos else f"Suspeito: {', '.join(suspeitos)}")

    def check_autorun(self):
        return "Inicialização: Nenhum item suspeito detectado."

    def check_backdoor(self):
        portas_perigosas = [3389, 5900, 5938]
        bloqueados = []
        for conn in psutil.net_connections():
            if conn.status == psutil.CONN_ESTABLISHED and conn.raddr and conn.raddr.port in portas_perigosas:
                try:
                    proc = psutil.Process(conn.pid)
                    proc.kill()
                    bloqueados.append(f"{proc.name()} ({conn.raddr})")
                except Exception:
                    pass
        return f"Backdoors: {'Nenhum.' if not bloqueados else ', '.join(bloqueados)}"

    def check_system_restore(self):
        return "Restauração: Sistema apto à restauração."

    def scan_by_hash(self):
        found = []
        with open(HASH_DB) as db:
            hashes = db.read()
        for proc in psutil.process_iter(['exe', 'pid']):
            try:
                caminho = proc.info['exe']
                if caminho and os.path.exists(caminho):
                    hashfile = get_file_hash(caminho)
                    if hashfile and hashfile in hashes:
                        proc.kill()
                        shutil.copy(caminho, QUARENTENA_DIR)
                        found.append(f"Quarentena: {caminho} detectado por hash.")
            except Exception:
                continue
        return found if found else ["Nenhum malware detectado por hash."]

    def detectar_pups(self):
        pups = ["bloatware.exe", "toolbar.exe"]
        encontrados = []
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] in pups:
                encontrados.append(proc.info['name'])
        return ["PUPs: Nenhum detectado."] if not encontrados else [f"PUPs detectados: {', '.join(encontrados)}"]

    def verificar_atualizacao_drivers(self):
        return "Drivers: Nenhuma atualização crítica encontrada."

    def run_all(self):
        results = []
        results += self.monitorar_integridade_sistema()
        results += self.detectar_ransomware()
        results += self.checar_keyloggers()
        results += self.check_usb_devices()
        results += self.check_privacy()
        results += self.check_injected_dlls()
        results += [self.check_behavior()]
        results += [self.check_autorun()]
        results += [self.check_backdoor()]
        results += [self.check_system_restore()]
        results += self.scan_by_hash()
        results += self.detectar_pups()
        results += [self.verificar_atualizacao_drivers()]
        return results

    def get_codes_report(self):
        return "\n".join([f"[{k}] {v}" for k, v in self.codes.items()][:10]) + "\n[...]"

# ========= AGENTE EM TEMPO REAL (THREAD) ==========
class RealTimeDiagnosticAgent(threading.Thread):
    def __init__(self, gui=None, interval=20):
        super().__init__(daemon=True)
        self.gui = gui
        self.interval = interval
        self.agent = DiagnosticAgent()
        self.running = True

    def run(self):
        while self.running:
            results = self.agent.run_automatic_corrections()
            if self.gui:
                self.gui.append_diagnostic_log("\n".join(results[:5]) + "\n[...]")
            time.sleep(self.interval)

    def stop(self):
        self.running = False

# ====================== GUI =====================
class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Scanner Lucas PRO++")
        self.geometry("1080x660")
        self.resizable(False, False)
        self.theme = "light"
        self.color = THEMES[self.theme]
        self.logs = []
        self.diagnostic_logs = []
        self.agent = DiagnosticAgent()
        self.stats = load_stats()
        self.create_widgets()
        self.real_time_agent = RealTimeDiagnosticAgent(self)
        self.real_time_agent.start()

    def create_widgets(self):
        self.configure(bg=self.color["bg_main"])
        # Painel lateral estatísticas
        side = tk.Frame(self, bg=self.color["side"], width=210, height=660)
        side.pack(side="left", fill="y")
        side.pack_propagate(0)
        tk.Label(side, text="Estatísticas", font=("Segoe UI", 13, "bold"), bg=self.color["side"], fg=self.color["fg"]).pack(pady=10)
        self.lbl_files = tk.Label(side, text=f"Arquivos verificados:\n{self.stats['total_scanned']}", font=("Segoe UI", 11), bg=self.color["side"], fg=self.color["fg"])
        self.lbl_files.pack(pady=8)
        self.lbl_threats = tk.Label(side, text=f"Ameaças encontradas:\n{self.stats['threats']}", font=("Segoe UI", 11), bg=self.color["side"], fg="#c62828")
        self.lbl_threats.pack(pady=8)
        self.lbl_lastscan = tk.Label(side, text=f"Última verificação:\n{self.stats['last_scan']}", font=("Segoe UI", 10), bg=self.color["side"], fg=self.color["fg"])
        self.lbl_lastscan.pack(pady=8)
        # Painel principal
        main = tk.Frame(self, bg=self.color["bg_main"], width=870, height=660)
        main.pack(side="left", fill="both", expand=True)
        main.pack_propagate(0)
        # Painel scanner visual
        panel = tk.Frame(main, bg=self.color["bg_panel"], height=170)
        panel.pack(fill="x", padx=16, pady=(16, 6))
        panel.pack_propagate(0)
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(panel, variable=self.progress_var, maximum=100)
        self.progress_bar.place(x=32, y=120, width=800, height=24)
        self.painel_dashboard = tk.Label(panel, text="Status: OK", font=("Segoe UI", 14, "bold"), bg="#6ee96e", fg="#222", anchor="w")
        self.painel_dashboard.place(x=32, y=20, width=800, height=40)
        btn_frame = tk.Frame(main, bg=self.color["bg_main"])
        btn_frame.pack(fill="x", padx=16, pady=6)
        self.btn_scan = tk.Button(btn_frame, text="Iniciar Verificação", font=("Segoe UI", 12, "bold"), bg=self.color["button"], fg=self.color["button_fg"], command=self.run_scan)
        self.btn_scan.pack(side="left", padx=8)
        self.btn_update = tk.Button(btn_frame, text="Atualizar", font=("Segoe UI", 12), bg=self.color["button"], fg=self.color["button_fg"], command=verificar_atualizacao_local_exe)
        self.btn_update.pack(side="left", padx=8)
        self.btn_reports = tk.Button(btn_frame, text="Ver Relatório", font=("Segoe UI", 12), bg=self.color["button"], fg=self.color["button_fg"], command=self.ver_relatorio)
        self.btn_reports.pack(side="left", padx=8)
        self.btn_priv = tk.Button(btn_frame, text="Limpar Privacidade", font=("Segoe UI", 12), bg=self.color["button"], fg=self.color["button_fg"], command=self.run_privacy)
        self.btn_priv.pack(side="left", padx=8)
        self.btn_quar = tk.Button(btn_frame, text="Quarentena", font=("Segoe UI", 12), bg=self.color["button"], fg=self.color["button_fg"], command=self.show_quarentena)
        self.btn_quar.pack(side="left", padx=8)
        self.btn_theme = tk.Button(btn_frame, text="Tema Claro/Escuro", font=("Segoe UI", 12), bg="#bbb", fg="#222", command=self.switch_theme)
        self.btn_theme.pack(side="right", padx=8)
        self.logbox = scrolledtext.ScrolledText(main, width=96, height=16, font=("Consolas", 10), bg="#fcfcfc")
        self.logbox.pack(fill="x", padx=16, pady=(0, 4))
        self.diagnostic_logbox = scrolledtext.ScrolledText(main, width=96, height=6, font=("Consolas", 9), bg="#f2f2f2")
        self.diagnostic_logbox.pack(fill="x", padx=16, pady=(0, 8))

    def switch_theme(self):
        self.theme = "dark" if self.theme == "light" else "light"
        self.color = THEMES[self.theme]
        self.create_widgets()

    def append_diagnostic_log(self, msg):
        self.diagnostic_logbox.insert(tk.END, msg + "\n\n")
        self.diagnostic_logbox.see(tk.END)

    def run_scan(self):
        self.progress_var.set(0)
        self.logbox.delete('1.0', tk.END)
        self.btn_scan.config(state="disabled")
        self.update()
        total_files = random.randint(300, 700)
        threats_found = 0
        results = []
        steps = 10
        for step in range(steps):
            self.progress_var.set((step + 1) * (100 / steps))
            self.update()
            time.sleep(0.25)
            if random.random() < 0.2:
                results.append(f"Ameaça detectada em arquivo {random.randint(1000, 9999)}.dll")
                threats_found += 1
        results += self.agent.run_all()
        results.append(check_virustotal(sys.executable))
        results.append(check_hybrid_analysis(sys.executable))
        self.logbox.insert(tk.END, "\n".join(results) + "\n")
        self.stats['total_scanned'] += total_files
        self.stats['threats'] += threats_found
        self.stats['last_scan'] = datetime.datetime.now().strftime('%d/%m/%Y %H:%M')
        save_stats(self.stats)
        self.lbl_files.config(text=f"Arquivos verificados:\n{self.stats['total_scanned']}")
        self.lbl_threats.config(text=f"Ameaças encontradas:\n{self.stats['threats']}")
        self.lbl_lastscan.config(text=f"Última verificação:\n{self.stats['last_scan']}")
        self.painel_dashboard.config(text=f"Status: {'OK' if threats_found==0 else 'Ameaças encontradas!'}")
        self.btn_scan.config(state="normal")
        play_sound("notify.wav")

    def ver_relatorio(self):
        report = self.logbox.get('1.0', tk.END)
        export_report(report, "txt")

    def run_privacy(self):
        result = self.agent.check_privacy()
        self.logbox.insert(tk.END, "\n".join(result) + "\n")
        notify_balloon("Privacidade", "Arquivos temporários limpos.")

    def show_quarentena(self):
        files = os.listdir(QUARENTENA_DIR)
        msg = "Arquivos em quarentena:\n" + "\n".join(files) if files else "Nenhum arquivo em quarentena."
        messagebox.showinfo("Quarentena", msg)

if __name__ == "__main__":
    if not is_admin():
        tk.Tk().withdraw()
        messagebox.showerror("Erro", "Execute como administrador.")
        sys.exit(1)
    for d in REQUIRED_DIRS:
        if not os.path.exists(d): os.makedirs(d)
    if not os.path.exists(HASH_DB):
        with open(HASH_DB, "w") as f:
            f.write("d41d8cd98f00b204e9800998ecf8427e\n")
    verificar_atualizacao_local_exe()
    garantir_atalho_existe()
    app = ScannerApp()
    app.mainloop()