import subprocess
import sys

def run_command(cmd):
    process = subprocess.Popen(cmd, shell=True)
    process.communicate()
    if process.returncode != 0:
        sys.exit(process.returncode)

def main():
    # Executa os testes existentes e gera relatório de cobertura no terminal
    print("Executando testes existentes...")
    run_command("pytest --maxfail=1 --disable-warnings -q")
    
    print("Executando testes com análise de cobertura...")
    run_command("pytest --cov=. --cov-report=term-missing")

if __name__ == "__main__":
    main()
