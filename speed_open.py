# Importação da biblioteca para operações de codificação e decodificação em base64.
# Base64 é um método de codificação utilizado para converter dados binários em uma cadeia de caracteres ASCII, comum em transferências de dados via internet.
import base64  

# Importação da biblioteca para geração de hash.
# Hashing é um processo de transformação de uma grande quantidade de dados em uma pequena quantidade de informação tipicamente representada por um valor hash.
import hashlib  

# Importação de módulos relacionados à criptografia AES (Advanced Encryption Standard).
# AES é um algoritmo de criptografia simétrica, que usa a mesma chave para cifrar e decifrar informações, garantindo a confidencialidade dos dados.
from Crypto.Cipher import AES  

# Importação do módulo para criptografia Blowfish.
# Blowfish é um algoritmo de criptografia simétrica desenhado para substituir o DES ou IDEA, oferecendo uma boa velocidade e segurança.
from Crypto.Cipher import Blowfish

# Importação de métodos para adicionar ou remover padding (preenchimento) a blocos de dados.
# O padding é necessário quando o tamanho dos dados não é suficiente para preencher o último bloco na criptografia de bloco.
from Crypto.Util.Padding import unpad, pad  

# Importação de PBKDF2, uma função de derivação de chave baseada em senha.
# PBKDF2 aplica uma função criptográfica de hash, como SHA-256, junto com um salto e iterações para produzir a chave derivada, aumentando a segurança contra ataques de força bruta.
from Crypto.Protocol.KDF import PBKDF2

# Importação de método para gerar bytes aleatórios.
# Esses bytes podem ser utilizados para criar chaves criptográficas ou vetores de inicialização (IVs) que necessitam de valores aleatórios e seguros.
from Crypto.Random import get_random_bytes  

# Importação da função b64decode da biblioteca base64.
# Essa função é usada para decodificar dados codificados em base64, revertendo-os para sua forma binária original.
from base64 import b64decode

# Importação da biblioteca functools e da função partial.
# Partial é usada para criar uma nova função com alguns argumentos fixos baseados em uma função existente, facilitando a reutilização de funções com parâmetros comuns.
from functools import partial

# Importação da biblioteca para manipulação de JSON.
# JSON (JavaScript Object Notation) é um formato de texto para armazenar e transportar dados, sendo fácil para humanos lerem e escreverem, além de fácil para máquinas parsearem e gerarem.
import json
# Importa o módulo requests para lidar com requisições HTTP.
# O módulo requests é amplamente utilizado para enviar requisições HTTP de maneira simples e intuitiva, permitindo interagir com APIs ou outros recursos da web.
import requests  

# Importa HTTPAdapter do módulo requests.adapters.
# HTTPAdapter é utilizado para configurar opções avançadas de sessões HTTP, como retries (tentativas repetidas em caso de falhas) e backoff factors.
from requests.adapters import HTTPAdapter  

# Importa Retry do módulo requests.packages.urllib3.util.retry.
# A classe Retry é usada para definir políticas de tentativa repetida de requisições, permitindo configurar o número máximo de retries, status codes para retry, entre outros.
from requests.packages.urllib3.util.retry import Retry  

# Importa exceções específicas do módulo requests para melhor tratamento de erros.
# RequestException e ConnectionError são exemplos de exceções que podem ser capturadas para lidar com erros de conexão ou falhas na requisição.
from requests.exceptions import RequestException, ConnectionError  

# Importa o módulo time para lidar com temporizações e delays em execuções.
# O módulo time é fundamental para operações que exigem pausas, como esperar um tempo antes de realizar novas tentativas de requisições HTTP.
import time

def verificar_conexao_internet(timeout=15):
    """Função para verificar se há conexão à internet durante um determinado tempo."""
    print("Verificando conexão à internet...")
    tempo_inicial = time.time()  # Registra o tempo inicial da verificação
    while time.time() - tempo_inicial < timeout:  # Realiza a verificação dentro do limite de tempo
        try:
            requests.get("http://www.google.com", timeout=1)  # Tenta fazer uma requisição ao Google
            print("Conexão estabelecida.")
            return True  # Retorna True se a conexão for estabelecida com sucesso
        except requests.ConnectionError:
            print("Sem conexão à internet. Tentando novamente...")
            time.sleep(1)  # Aguarda 1 segundo antes de tentar novamente
    print(f"Falha ao estabelecer conexão após {timeout} segundos.")
    return False  # Retorna False se não conseguir estabelecer conexão dentro do tempo limite

def baixar_arquivo_com_retry(url, nome_arquivo, max_tentativas=20, intervalo=5):
    """Função para baixar um arquivo da web com tentativas de retry e intervalo de tempo entre as tentativas."""
    if not verificar_conexao_internet():  # Verifica se há conexão à internet antes de iniciar
        print("Sem conexão à internet. Impossível baixar o arquivo.")
        #return  # Sai da função se não houver conexão
        exit() # Corre Berg

    session = requests.Session()  # Cria uma sessão HTTP para persistir configurações
    retries = Retry(total=max_tentativas, backoff_factor=1, status_forcelist=[403, 404, 500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))  # Configura retries para HTTP
    session.mount('https://', HTTPAdapter(max_retries=retries))  # Configura retries para HTTPS

    for i in range(1, max_tentativas + 1):
        print(f"Tentativa {i}/{max_tentativas}")
        try:
            response = session.get(url, headers={'User-Agent': 'Mozilla/5.0'})  # Faz a requisição GET
            response.raise_for_status()  # Levanta uma exceção para status de resposta HTTP inválidos
            with open(nome_arquivo, 'wb') as f:  # Abre o arquivo em modo de escrita binária
                f.write(response.content)  # Escreve o conteúdo da resposta no arquivo
            print("Arquivo baixado com sucesso!")
            return  # Sai da função após o download bem-sucedido
        except RequestException as e:  # Captura exceções relacionadas a requisições
            print(f"Erro: {e}")  # Imprime o erro ocorrido durante a requisição
            if i < max_tentativas:  # Verifica se ainda há tentativas restantes
                print(f"Tentando novamente em {intervalo} segundos...")
                time.sleep(intervalo)  # Aguarda o intervalo de tempo especificado antes de tentar novamente
            else:
                print("Número máximo de tentativas alcançado. Falha ao baixar o arquivo.")
                return  # Sai da função após atingir o número máximo de tentativas
        except ConnectionError:
            print("Conexão perdida. Tentando novamente...")
            if i < max_tentativas:
                time.sleep(intervalo)  # Aguarda o intervalo de tempo especificado antes de tentar novamente
            else:
                print("Número máximo de tentativas alcançado. Falha ao baixar o arquivo.")
                # return  # Sai da função após atingir o número máximo de tentativas
                exit() # Corre Berg

url = 'https://raw.githubusercontent.com/El-Patron-2003/INTERNET-GRATIS-LATINO/main/Speed%20Tunnel%20VPN'  # URL do arquivo a ser baixado
nome_arquivo = 'enc.txt'  # Nome do arquivo de destino após o download

# Chama a função 'baixar_arquivo_com_retry' para baixar o arquivo com tentativas de retry e intervalo de tempo entre as tentativas
baixar_arquivo_com_retry(url, nome_arquivo)

class CriptografiaAES:
    # Alvo padrão para o modo de operação CBC
    alvo = bytes([0]*16)
    
    def __init__(self, chave, ch2=""):
        """
        Inicializa a classe com a chave e um valor opcional para ch2.
        
        Args:
            chave (str): A chave de criptografia.
            ch2 (str, opcional): Outro valor opcional. Padrão é uma string vazia.
        """
        self.chave = chave
        self.ch2 = ch2
    
    @staticmethod
    def decodificar_base64(s):
        """
        Decodifica uma string codificada em base64.
        
        Args:
            s (str): String codificada em base64.
        
        Returns:
            str: String decodificada.
        """
        resultado = base64.b64decode(s).decode('utf-8')
        return resultado

    @staticmethod
    def decodificar_bytes(barray):
        """
        Decodifica uma sequência de bytes usando uma tabela de caracteres específica.
        
        Args:
            barray (bytes): Sequência de bytes a ser decodificada.
        
        Returns:
            str: String decodificada.
        """
        caracteres = "▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐"
        resultado = ""
        for b in barray:
            resultado += caracteres[(b & 240) >> 4]
            resultado += caracteres[b & 15]
        return resultado

    @staticmethod
    def decodificar_hexadecimal(barray):
        """
        Decodifica uma sequência de bytes em formato hexadecimal.
        
        Args:
            barray (bytes): Sequência de bytes a ser decodificada.
        
        Returns:
            str: String hexadecimal decodificada.
        """
        caracteres = "0123456789ABCDEF"
        resultado = ""
        for b in barray:
            resultado += caracteres[(b & 240) >> 4]
            resultado += caracteres[b & 15]
        return resultado

    @staticmethod
    def bytes_para_hexadecimal(bArr):
        """
        Converte uma sequência de bytes em uma string hexadecimal.
        
        Args:
            bArr (bytes): Sequência de bytes a ser convertida.
        
        Returns:
            str: String hexadecimal.
        """
        caracteres = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']
        caracteres2 = [' '] * (len(bArr) * 2)
        for i in range(len(bArr)):
            i2 = bArr[i] & 255
            i3 = i * 2
            caracteres2[i3] = caracteres[i2 >> 4]
            caracteres2[i3 + 1] = caracteres[i2 & 15]
        return ''.join(caracteres2)

    def codificar_ja(self, s):
        """
        Codifica uma string usando um método específico.
        
        Args:
            s (str): String a ser codificada.
        
        Returns:
            str: String codificada.
        """
        resultado = self.decodificar_bytes(bytes(s, encoding="utf8"))
        return resultado

    def codificar_ja_chaves(self, s):
        """
        Codifica uma string em formato hexadecimal.
        
        Args:
            s (str): String a ser codificada.
        
        Returns:
            str: String hexadecimal.
        """
        resultado = self.decodificar_hexadecimal(bytes(s, encoding="utf8"))
        return resultado

    @staticmethod
    def gerar_string(input_str):
        """
        Gera uma string baseada em uma lista de caracteres específica.
        
        Args:
            input_str (str): String de entrada.
        
        Returns:
            str: String gerada.
        """
        caracteres = "▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐"
        lista_caracteres = list(input_str)
        comprimento = len(input_str) // 2
        bArr = bytearray(comprimento)
        for i in range(comprimento):
            i2 = i * 2
            bArr[i] = (caracteres.index(lista_caracteres[i2]) * 16 + caracteres.index(lista_caracteres[i2 + 1])) & 255
        return bArr.decode('utf-8')

    @staticmethod
    def criar_digesto_sha256(input_str):
        """
        Cria um digesto SHA-256 para uma string de entrada.
        
        Args:
            input_str (str): String de entrada.
        
        Returns:
            bytes: Digesto SHA-256.
        """
        message_digest = hashlib.sha256()
        message_digest.update(input_str.encode('utf-8'))
        digest = message_digest.digest()
        return digest

    @staticmethod
    def decifrar_bytes_chave_secreta(chave_secreta, iv, texto_cifrado):
        """
        Decifra bytes usando uma chave secreta e um vetor de inicialização (IV).
        
        Args:
            chave_secreta (bytes): Chave secreta.
            iv (bytes): Vetor de inicialização.
            texto_cifrado (bytes): Bytes a serem decifrados.
        
        Returns:
            bytes: Bytes decifrados.
        """
        cipher = AES.new(key=chave_secreta, mode=AES.MODE_CBC, iv=iv)
        dados_decifrados = cipher.decrypt(texto_cifrado)
        return unpad(dados_decifrados, AES.block_size)

    def decifrar_string(self, entrada):
        """
        Decifra uma string de entrada usando uma chave e um valor opcional.
        
        Args:
            entrada (str): String de entrada a ser decifrada.
        
        Returns:
            str: String decifrada.
        """
        str1 = self.chave
        str2 = entrada
        str3 = self.ch2
        string_gerada = self.gerar_string(str2)
        chave_ja = str3 + self.codificar_ja_chaves(str1)
        chave_secreta = self.criar_digesto_sha256(chave_ja)
        decofificar = base64.b64decode(string_gerada)
        descifrado = self.decifrar_bytes_chave_secreta(chave_secreta, self.alvo, decofificar)
        str3 = str(descifrado, encoding="utf8")
        return str3
    
    @staticmethod
    def decBlowfish(entrada, key):
        """
        Decifra uma string usando o algoritmo Blowfish.
        
        Args:
            entrada (str): Texto cifrado em base64.
            key (str): Chave de criptografia.
        
        Returns:
            str: Texto decifrado.
        """
        iv = b'abcdefgh'  # IV deve ter 8 bytes para Blowfish
        cipher = Blowfish.new(key.encode(), Blowfish.MODE_CBC, iv)
        b64 = base64.b64decode(entrada.replace("\\+s", ""))
        decrypted_text = unpad(cipher.decrypt(b64), Blowfish.block_size)
        return decrypted_text.decode()

    @staticmethod
    def cifrar_bytes_chave_secreta(chave_secreta, iv, texto):
        """
        Cifra bytes usando uma chave secreta e um vetor de inicialização (IV).
        
        Args:
            chave_secreta (bytes): Chave secreta.
            iv (bytes): Vetor de inicialização.
            texto (bytes): Bytes a serem cifrados.
        
        Returns:
            bytes: Bytes cifrados.
        """
        cipher = AES.new(chave_secreta, AES.MODE_CBC, iv)
        dados_padronizados = pad(texto, AES.block_size)
        dados_cifrados = cipher.encrypt(dados_padronizados)
        return dados_cifrados
        
    @staticmethod
    def decryptN2(encoded_str):
        """
        Decifra uma string codificada em base64 usando AES.
        
        Args:
            encoded_str (str): String codificada em base64.
        
        Returns:
            str: Texto decifrado.
        """
        if not encoded_str:
            return ""
        decoded = base64.b64decode(encoded_str)
        iv = decoded[:16]
        ciphertext = decoded[16:]
        salt = b"MySalt"
        password = b"_w3Bl;RNjuquu#D"
        key = PBKDF2(password, salt, dkLen=32, count=1000)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext).decode("utf-8").rstrip('\x00')
        decrypted_cleaned = "".join(char for char in decrypted if 32 <= ord(char) <= 126)
        return decrypted_cleaned

    def cifrar_string(self, str1, str2):
        """
        Cifra uma string usando AES e uma chave secreta derivada da string de entrada.
        
        Args:
            str1 (str): String a ser utilizada na derivação da chave.
            str2 (str): String a ser cifrada.
        
        Returns:
            str: Texto cifrado em base64.
        """
        chave_ja = self.codificar_ja_chaves(str1)
        chave_secreta = self.criar_digesto_sha256(chave_ja)
        cifrar = self.cifrar_bytes_chave_secreta(chave_secreta, self.alvo, bytes(str2, 'utf-8'))
        encode = base64.b64encode(cifrar).decode('utf-8')
        codificar_ja = self.codificar_ja(encode)
        return codificar_ja

def isJaCodes(str1):
    """
    Verifica se uma string contém apenas caracteres específicos.
    
    Args:
        str1 (str): String a ser verificada.
    
    Returns:
        bool: True se a string contiver apenas caracteres específicos, False caso contrário.
    """
    caracteres = "▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐"
    if all(char for char in str1 if (char in caracteres)):
        return True

def decrypt_json_values(obj, decoder, tip=""):
    """
    Decifra os valores de um objeto JSON de forma recursiva.
    
    Args:
        obj (dict, list, str): Objeto JSON a ser decifrado.
        decoder (function): Função de decodificação a ser aplicada aos valores.
        tip (str, opcional): Tipo opcional de decodificação. Padrão é uma string vazia.
    
    Returns:
        dict, list, str: Objeto JSON decifrado.
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            obj[key] = decrypt_json_values(value, decoder)
    elif isinstance(obj, list):
        for i in range(len(obj)):
            obj[i] = decrypt_json_values(obj[i], decoder)
    elif isinstance(obj, str):
        # Verificar se a string é codificada em base64 antes de tentar decodificar e descriptografar
        if isJaCodes(obj):
            try:
                obj = decoder(obj)
            except (UnicodeDecodeError, ValueError):
                pass
        # Decodificar de acordo com o tipo especificado
        elif tip == "pkb":
            obj = decoder(obj)
        # Tentar decodificar a string
        elif "=" in obj:
            try:
                obj = decoder(obj)
            except ValueError:
                pass
        else:
            # Tentar decodificar os bytes diretamente para UTF-8
            try:
                obj = bytes(obj, 'utf-8').decode('utf-8', 'ignore')
            except UnicodeDecodeError:
                pass
    return obj

# Abrir o arquivo "enc.txt" para leitura
with open("enc.txt", 'r') as file:
    # Ler o conteúdo do arquivo e remover espaços em branco extras
    entrada = file.read().strip()

# Definir a chave e o valor opcional ch2 para a classe CriptografiaAES
chave = "Michoose238TariF}"
ch2 =  ""

# Criar uma instância da classe CriptografiaAES
testes = CriptografiaAES(chave, ch2)

# Decifrar a entrada usando a função decifrar_string da classe CriptografiaAES
res = testes.decifrar_string(entrada)

# Imprimir informações sobre a entrada, chave e saída decifrada
print("----- Informações -----")  # Início da seção de informações
print(f"[+] Entrada : {entrada[0:10]}...")  # Exibir os primeiros 10 caracteres da entrada
print(f"[+] Chave : {chave}")  # Exibir a chave de criptografia utilizada
print(f"[+] Saída :")  # Indicar que a saída será exibida em seguida
# Imprimir os primeiros 30 caracteres da saída decifrada
print(res[:30])  # Exibir os primeiros 30 caracteres da saída decifrada

# Abrir o arquivo "config.json" para escrita, usando UTF-8 para codificação
with open("config.json", "w", encoding='utf-8') as f_saida:
    # Carregar a saída decifrada como um objeto JSON
    res2 = json.loads(res)
    # Definir a função de decodificação como decryptN2 da classe CriptografiaAES
    decoder = testes.decryptN2
    # Decifrar os valores do objeto JSON usando a função decrypt_json_values
    res3 = decrypt_json_values(res2, decoder)
    # Escrever o objeto JSON decifrado no arquivo de saída com indentação de 4 espaços
    f_saida.write(json.dumps(res3, ensure_ascii=False, indent=4))
