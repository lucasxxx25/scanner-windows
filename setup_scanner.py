import subprocess
import sys
import os
import urllib.request

def instalar_requisitos():
    requisitos = ["psutil", "pefile", "requests"]
    for pacote in requisitos:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pacote])
            print(f"{pacote} instalado com sucesso.")
        except subprocess.CalledProcessError:
            print(f"Erro ao instalar o pacote: {pacote}")

def baixar_arquivos():
    arquivos = {
        "scanner_gui.py": "https://raw.githubusercontent.com/lucasxxx25/scanner-windows/main/scanner_gui.py"
    }
    for nome, url in arquivos.items():
        try:
            print(f"Baixando {nome}...")
            urllib.request.urlretrieve(url, nome)
            print(f"{nome} baixado com sucesso.")
        except Exception as e:
            print(f"Erro ao baixar {nome}: {e}")

if __name__ == "__main__":
    instalar_requisitos()
    baixar_arquivos()
    print("\nTudo pronto. Execute 'scanner_gui.py' para iniciar a interface.")
    input("Pressione Enter para sair...")
Add setup_scanner.py para instalação automática
