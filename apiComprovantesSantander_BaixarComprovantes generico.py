import requests
import json
import time
import os
import logging 
from datetime import datetime, timedelta

# --- CONTROLE DE LOG DETALHADO ---
LOG_LEVEL_GLOBAL = logging.ERROR  # Mude para logging.INFO ou logging.ERROR para menos logs

# --- Configuração Inicial do Logging ---
log_format = '%(asctime)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s' 
logging.basicConfig(level=LOG_LEVEL_GLOBAL, format=log_format, force=True) 

# --- URLs e Configurações ---
# AMBIENTE SANDBOX 
TOKEN_URL_SANDBOX = "https://trust-sandbox.api.santander.com.br/auth/oauth/v2/token"
PAYMENT_RECEIPTS_API_SANDBOX_BASE = "https://trust-sandbox.api.santander.com.br/consult_payment_receipts/v1/payment_receipts"
CLIENT_ID_SANDBOX = "" #Defina aqui o CLIENT_ID do ambiente de sandbox
CLIENT_SECRET_SANDBOX = "" #Defina aqui o CLIENT_SECRET do ambiente de sandbox 
X_APP_KEY_SANDBOX = CLIENT_ID_SANDBOX 
CAMINHO_CERTIFICADO_SANDBOX_PEM = "certificate.pem" #Defina aqui o caminho do certificado PEM do ambiente de sandbox
VERIFICAR_SSL_SANDBOX = True 

# AMBIENTE DE PRODUÇÃO 
TOKEN_URL_PRODUCAO = "https://trust-open.api.santander.com.br/auth/oauth/v2/token" 
PAYMENT_RECEIPTS_API_PRODUCAO_BASE = "https://trust-open.api.santander.com.br/consult_payment_receipts/v1/payment_receipts"
CLIENT_ID_PRODUCAO = "" #Defina aqui o CLIENT_ID do ambiente de produção
CLIENT_SECRET_PRODUCAO = "" #Defina aqui o CLIENT_SECRET do ambiente de produção
X_APP_KEY_PRODUCAO = CLIENT_ID_PRODUCAO 
CAMINHO_CERTIFICADO_PRODUCAO_PEM = "" #Defina aqui o caminho do certificado PEM do ambiente de produção
VERIFICAR_SSL_PRODUCAO = True 

# Configuração Geral 
PASTA_DOWNLOAD_COMPROVANTES = "./comprovantes_baixados" # Defina aqui o caminho da pasta onde os comprovantes serão baixados
MAX_RETRIES = 3
RETRY_DELAY = 5 # Segundos

# --- Classe de Autenticação ---
class SantanderAuthManager:
    def __init__(self, client_id, client_secret, token_url, cert_path, verify_ssl=True, session=None):
        self.client_id = client_id; self.client_secret = client_secret; self.token_url = token_url
        self.cert_path = cert_path; self.verify_ssl = verify_ssl
        self._access_token = None; self._token_expiry_time = 0; self.token_info_completa = None
        self.session = session if session else requests.Session() 
        logging.debug(f"AuthManager inicializado. ClientID: {self.client_id}, TokenURL: {self.token_url}")

    def _log_request_details(self, method: str, url: str, headers: dict = None, data_payload = None):
        logging.debug(f"API Request (Token):")
        logging.debug(f"  -> Method : {method}"); logging.debug(f"  -> URL    : {url}")
        if headers: logging.debug(f"  -> Headers: {headers}")
        if data_payload: logging.debug(f"  -> Body(D): {data_payload}") 
        logging.debug(f"  -> Cert   : {self.cert_path}"); logging.debug(f"  -> Verify : {self.verify_ssl}")

    def _log_response_details(self, response_struct: dict):
        logging.debug(f"  <-- Token Response Status : {response_struct.get('status_code', 'N/A')}")
        logging.debug(f"  <-- Token Response Headers: {dict(response_struct.get('headers', {}))}") 
        body = response_struct.get('data')
        if response_struct.get('is_json'):
            if isinstance(body, (dict, list)): logging.debug(f"  <-- Token Response Body (JSON):\n{json.dumps(body, indent=2)}")
            else: logging.warning(f"  <-- Token Response Body (JSON esperado, tipo {type(body)}): {str(body)[:500]}...")
        else: logging.debug(f"  <-- Token Response Body (Texto): {str(body)[:500]}...")

    def _fetch_new_token(self):
        payload_req = {'client_id': self.client_id,'client_secret': self.client_secret,'grant_type': 'client_credentials'}
        payload_log = {'client_id': self.client_id,'client_secret': '***SECRET***','grant_type': 'client_credentials'}
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        logging.info(f"Tentando obter novo token de: {self.token_url}")
        self._log_request_details("POST", self.token_url, headers=headers, data_payload=payload_log)
        last_exc = None
        for attempt in range(MAX_RETRIES):
            try:
                response = self.session.post(self.token_url, data=payload_req, headers=headers, 
                                         cert=self.cert_path, verify=self.verify_ssl, timeout=30) 
                api_resp = format_api_response(response); 
                self._log_response_details(api_resp) 
                response.raise_for_status()
                self.token_info_completa = api_resp.get('data', {}) 
                if api_resp.get('is_json') and isinstance(self.token_info_completa, dict) and 'access_token' in self.token_info_completa:
                    self._access_token = self.token_info_completa['access_token']
                    exp_in = self.token_info_completa.get('expires_in', 3600); self._token_expiry_time = time.time() + exp_in - 60 
                    logging.info(f"Novo token obtido. Expira aprox.: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self._token_expiry_time))}")
                    return self._access_token
                else: 
                    logging.error(f"Erro: 'access_token' não encontrado ou resposta não é JSON. Data: {self.token_info_completa}")
                    return None 
            except requests.exceptions.HTTPError as http_e:
                last_exc = http_e; logging.error(f"Erro HTTP {http_e.response.status_code if http_e.response else 'N/A'} (Token, Tentativa {attempt+1})")
                if http_e.response is not None and http_e.response.status_code >= 500 and attempt < MAX_RETRIES - 1: time.sleep(RETRY_DELAY); continue 
                else: break 
            except requests.exceptions.RequestException as req_e: 
                last_exc = req_e; logging.error(f"Erro Conexão/Timeout (Token, Tentativa {attempt+1}): {req_e}")
                if attempt < MAX_RETRIES - 1: time.sleep(RETRY_DELAY); continue 
                else: break 
            except Exception as e: last_exc = e; logging.exception(f"Erro inesperado (Token, Tentativa {attempt+1})"); break 
        logging.error(f"Falha ao obter token. Último erro: {last_exc}"); self._access_token=None; self._token_expiry_time=0; return None

    def get_access_token(self):
        if self._access_token and time.time() < self._token_expiry_time: logging.debug("Usando token existente."); return self._access_token
        else: return self._fetch_new_token()
    def get_client_certificate_path(self): return self.cert_path
    def get_ssl_verify_option(self): return self.verify_ssl

# --- Helper para padronizar retornos ---
def format_api_response(response: requests.Response):
    data=None; is_json=False; status=response.status_code if response is not None else None
    hdrs=dict(response.headers) if response is not None else {}
    txt=None
    try:
        txt=response.text if response is not None else None
        if txt: data=json.loads(txt); is_json=True
        else: data="" 
    except (ValueError, json.JSONDecodeError): data=txt 
    except Exception as e: logging.warning(f"Erro ao ler/parsear corpo da resposta: {e}"); data="[Erro parse]"
    return {"status_code": status, "data": data, "is_json": is_json, "headers": hdrs}

# --- Funções Auxiliares de Logging ---
def _log_request_details(method: str, url: str, headers: dict = None, params: dict = None, json_payload: dict = None, data_payload = None, cert_path: str = None, verify_ssl: bool = None):
    if LOG_LEVEL_GLOBAL <= logging.DEBUG:
        logging.debug(f"API Request Details:")
        logging.debug(f"  -> Method : {method}"); logging.debug(f"  -> URL    : {url}")
        if headers:
            log_h = {k: (f"Bearer {v[7:20]}..." if k.lower()=='authorization' and isinstance(v,str) and v.lower().startswith('bearer ') else v) for k,v in headers.items() if k.lower()!='client_secret'}
            logging.debug(f"  -> Headers: {log_h}")
        if params: logging.debug(f"  -> Params : {params}")
        if json_payload is not None : logging.debug(f"  -> Body(J): {json.dumps(json_payload, indent=2)}")
        if data_payload is not None: logging.debug(f"  -> Body(D): {data_payload}") 
        if cert_path: logging.debug(f"  -> Cert   : {cert_path}")
        if verify_ssl is not None: logging.debug(f"  -> Verify : {verify_ssl}")

def _log_response_details(response_struct: dict): 
     if LOG_LEVEL_GLOBAL <= logging.DEBUG:
        logging.debug(f"  <-- Response Status : {response_struct.get('status_code', 'N/A')}")
        h_log = {k: response_struct.get('headers',{}).get(k) for k in response_struct.get('headers',{}) if k.lower() in ['content-type','content-length','date','server-timing','connection']}
        logging.debug(f"  <-- Response Headers (Sel): {h_log}") 
        body = response_struct.get('data'); prefix = "  <-- Response Body"
        if response_struct.get('is_json'):
            if isinstance(body,(dict,list)): logging.debug(f"{prefix} (JSON):\n{json.dumps(body,indent=2)}")
            else: logging.warning(f"{prefix} (JSON esperado, tipo {type(body)}): {str(body)[:1000]}...")
        else: logging.debug(f"{prefix} (Texto/Outro): {str(body)[:1000]}{'...' if len(str(body)) > 1000 else ''}")

# --- Função API Genérica com Retry ---
def make_api_request(api_session: requests.Session, method: str, url: str, 
                     auth_manager_for_cert_verify: SantanderAuthManager, 
                     app_key: str, 
                     func_name_for_log: str = "make_api_request", 
                     headers: dict = None, params: dict = None, json_payload: dict = None, 
                     stream: bool = False, specific_error_codes: list = None):
    access_token = auth_manager_for_cert_verify.get_access_token()
    if not access_token: 
        logging.error(f"Token não disponível para {func_name_for_log} ({method} {url}).")
        return {"status_code": "CLIENT_ERROR", "error_code":"TOKEN_UNAVAILABLE", "data":"Token não disponível", "is_json": True, "headers": {}}

    request_headers = {'Authorization':f'Bearer {access_token}', 'X-Application-Key':app_key}
    request_headers['Accept'] = 'application/json' 
    
    request_kwargs = {
        "method": method.upper(), "url": url, "headers": request_headers, "params": params,
        "cert": auth_manager_for_cert_verify.get_client_certificate_path(),
        "verify": auth_manager_for_cert_verify.get_ssl_verify_option(),
        "timeout": (10, 60), "stream": stream
    }
    
    data_for_log_request = None # Para log
    if method.upper() in ['POST', 'PUT', 'PATCH']:
        request_headers['Content-Type'] = 'application/json' 
        if json_payload == {}: 
            request_kwargs['data'] = "" 
            data_for_log_request = "'' (empty string for Content-Length:0)"
        elif json_payload is not None:
            request_kwargs['json'] = json_payload
            data_for_log_request = json_payload
    
    _log_request_details(method, url, headers=request_headers, params=params, 
                         json_payload=(data_for_log_request if isinstance(data_for_log_request, dict) else None),
                         data_payload=(data_for_log_request if isinstance(data_for_log_request, str) else None),
                         cert_path=auth_manager_for_cert_verify.get_client_certificate_path(),
                         verify_ssl=auth_manager_for_cert_verify.get_ssl_verify_option())
    
    last_exc = None
    for attempt in range(MAX_RETRIES):
        try:
            logging.info(f"Executando {func_name_for_log} (Tentativa {attempt+1}/{MAX_RETRIES}). URL (base): {url.split('?')[0]}") 
            response = api_session.request(**request_kwargs) 
            
            if not stream:
                api_resp = format_api_response(response); _log_response_details(api_resp)
            else:
                 logging.debug(f"  <-- Response Status (Stream): {response.status_code}")
                 logging.debug(f"  <-- Response Headers (Stream): {dict(response.headers)}")
                 api_resp = {"status_code": response.status_code, "data": None, "is_json": False, "headers": response.headers, "raw_response": response}
            
            if specific_error_codes and not stream and api_resp.get('is_json') and isinstance(api_resp.get('data'),dict) and api_resp['data'].get("errors"):
                for err in api_resp['data']["errors"]:
                    err_code = err.get("code")
                    if err_code in specific_error_codes: 
                        api_resp["error_code"] = err_code 
                        logging.warning(f"API ({func_name_for_log}) retornou erro específico {err_code} (Status {api_resp['status_code']}).")
                        return api_resp 
            
            if api_resp.get('status_code', 0) >= 500 and attempt < MAX_RETRIES - 1 and not stream:
                logging.warning(f"Erro {api_resp['status_code']} (Server Error) em {func_name_for_log}. Tentando novamente em {RETRY_DELAY}s... (Tentativa {attempt+1}/{MAX_RETRIES})")
                time.sleep(RETRY_DELAY); continue 
            response.raise_for_status() 
            if stream: return response, "STREAM_RESPONSE"
            else: return api_resp
        except requests.exceptions.HTTPError as http_e:
            last_exc=http_e; status_code_err = http_e.response.status_code if http_e.response else "N/A"
            logging.error(f"Erro HTTP {status_code_err} na Tentativa {attempt+1}/{MAX_RETRIES} ({func_name_for_log})")
            if not stream and http_e.response is not None: _log_response_details(format_api_response(http_e.response))
            if http_e.response is not None:
                 if http_e.response.status_code < 500: logging.warning("Erro 4xx (Client Error), não tentando novamente."); break
                 if attempt >= MAX_RETRIES - 1: logging.error("Número máximo de tentativas atingido para erro 5xx."); break
                 if attempt < MAX_RETRIES - 1 : logging.warning(f"Erro 5xx. Tentando novamente em {RETRY_DELAY}s..."); time.sleep(RETRY_DELAY)
                 else: break 
            else: break 
        except requests.exceptions.RequestException as req_e: 
             last_exc=req_e; logging.error(f"Erro de Requisição/Conexão ({func_name_for_log}, Tentativa {attempt+1}/{MAX_RETRIES}): {req_e}", exc_info=(LOG_LEVEL_GLOBAL <= logging.DEBUG))
             if attempt < MAX_RETRIES - 1: logging.warning(f"Tentando novamente em {RETRY_DELAY}s..."); time.sleep(RETRY_DELAY)
             else: logging.error("Número máximo de tentativas atingido para erro de conexão/timeout."); break
        except Exception as e: last_exc=e; logging.exception(f"Erro inesperado ({func_name_for_log}, Tentativa {attempt+1}/{MAX_RETRIES})"); break
    logging.error(f"Falha final ao executar {func_name_for_log} após {MAX_RETRIES if attempt == MAX_RETRIES-1 else attempt+1} tentativas.")
    if isinstance(last_exc,requests.exceptions.HTTPError) and hasattr(last_exc,'response') and last_exc.response is not None: return format_api_response(last_exc.response) 
    else: return {"status_code":"CLIENT_ERROR", "data":str(last_exc), "error_type":"UNKNOWN_OR_CONNECTION", "is_json":False, "headers":{}}

# --- Funções API específicas ---
def listar_comprovantes_pagamento(api_session: requests.Session, auth_manager: SantanderAuthManager, app_key: str, api_base_url: str,
                                 start_date_str: str, end_date_str: str, 
                                 limit: int = 100, offset: int = 0):
    func_name = "listar_comprovantes_pagamento"
    logging.info(f"Executando: {func_name}. Datas: {start_date_str} a {end_date_str}, Limite: {limit}")
    p = {'_limit': limit, '_offset': offset, 'start_date': start_date_str, 'end_date': end_date_str}
    result = make_api_request(api_session, "GET", api_base_url, auth_manager, app_key, func_name_for_log=func_name, params=p)
    if LOG_LEVEL_GLOBAL <= logging.INFO:
        if result and result.get("status_code") == 200: 
            item_count = 0
            if result.get('is_json') and isinstance(result.get('data'), dict): item_count = len(result['data'].get('paymentsReceipts', []))
            logging.info(f"Sucesso: {func_name}. Itens retornados: {item_count}")
        else: logging.error(f"Falha: {func_name}. Status: {result.get('status_code') if result else 'N/A'}")
    return result

def criar_solicitacao_arquivo_comprovante(api_session: requests.Session, auth_manager: SantanderAuthManager, app_key: str, api_base_url: str,
                                         payment_id: str, payload: dict = None):
    func_name = "criar_solicitacao_arquivo_comprovante"
    logging.info(f"Executando: {func_name}. PID: {payment_id}")
    url = f"{api_base_url}/{payment_id}/file_requests"
    d = payload if payload is not None else {} 
    result = make_api_request(api_session, "POST", url, auth_manager, app_key, func_name_for_log=func_name, json_payload=d, specific_error_codes=["006", "007"])
    return result

def listar_solicitacoes_de_arquivo_por_comprovante(api_session: requests.Session, auth_manager: SantanderAuthManager, app_key: str, api_base_url: str, 
                                                  payment_id: str, limit: int = 100, offset: int = 0):
    func_name = "listar_solicitacoes_de_arquivo_por_comprovante"
    logging.info(f"Executando: {func_name}. PID: {payment_id}")
    url = f"{api_base_url}/{payment_id}/file_requests"
    p = {'_limit': limit, '_offset': offset}
    result = make_api_request(api_session, "GET", url, auth_manager, app_key, func_name_for_log=func_name, params=p, specific_error_codes=["007"])
    return result

def obter_status_solicitacao_arquivo(api_session: requests.Session, auth_manager: SantanderAuthManager, app_key: str, api_base_url: str,
                                     payment_id: str, request_id: str):
    func_name = "obter_status_solicitacao_arquivo"
    logging.info(f"Executando: {func_name}. Req.ID {request_id}, PID: {payment_id}.")
    url = f"{api_base_url}/{payment_id}/file_requests/{request_id}"
    result = make_api_request(api_session, "GET", url, auth_manager, app_key, func_name_for_log=func_name)
    return result

def baixar_pdf_do_link(api_session: requests.Session, download_url: str, output_file_path: str, 
                       verify_ssl_for_download: bool # Este verify_ssl é para o domínio do link de download
                       ):
    func_name = "baixar_pdf_do_link"
    logging.info(f"Executando: {func_name}. URL: {download_url}")
    logging.info(f"Salvando em: {output_file_path}")
    last_exception = None
    for attempt in range(MAX_RETRIES):
        try:
            headers = {'User-Agent': 'Python Requests Script'} 
            _log_request_details("GET", download_url, headers=headers, verify_ssl=verify_ssl_for_download)
            # Para o download final, não passamos o mTLS cert da API principal, a menos que seja necessário
            response = api_session.get(download_url, stream=True, headers=headers, verify=verify_ssl_for_download, timeout=180) 
            
            logging.debug(f"  --> {func_name} Response Status (Tentativa {attempt+1}): {response.status_code}")
            ctype = response.headers.get('Content-Type', '').lower()
            logging.debug(f"  --> {func_name} Content-Type: {ctype}")
            if LOG_LEVEL_GLOBAL <= logging.DEBUG : _log_response_details(format_api_response(response)) 

            if response.status_code >= 500 and attempt < MAX_RETRIES -1 :
                logging.warning(f"Erro {response.status_code} ao baixar de {download_url}. Tentando novamente em {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY); continue
            response.raise_for_status()
            
            if 'application/pdf' in ctype:
                os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
                with open(output_file_path, 'wb') as f:
                    logging.debug(f"  Salvando PDF do link direto em {output_file_path}...")
                    for chunk in response.iter_content(chunk_size=8192*4): f.write(chunk)
                logging.info(f"PDF baixado do link direto e salvo em: {output_file_path}")
                return True
            else:
                logging.error(f"Erro: Link direto não retornou PDF. Content-Type: {ctype}")
                return False 
        except requests.exceptions.RequestException as e:
            last_exception = e
            logging.error(f"Erro HTTP/Request ({func_name}, Tentativa {attempt+1}) ao baixar de {download_url}: {e}", exc_info=(LOG_LEVEL_GLOBAL <= logging.DEBUG))
            if hasattr(e, 'response') and e.response is not None:
                 logging.error(f"Detalhes erro HTTP (Download Link): {e.response.status_code} - {e.response.text[:200]}")
            if attempt < MAX_RETRIES - 1: logging.warning(f"Tentando novamente em {RETRY_DELAY}s..."); time.sleep(RETRY_DELAY)
            else: break 
        except Exception as e:
            last_exception = e; logging.exception(f"Erro inesperado ({func_name}, Tentativa {attempt+1}) ao baixar de {download_url}"); break
    logging.error(f"Falha final ao baixar de {download_url} após {MAX_RETRIES} tentativas. Último erro: {last_exception}")
    return False

# --- Fluxo Principal ---
if __name__ == "__main__":
    # (O bloco if __name__ == "__main__" permanece o mesmo da resposta anterior, 
    #  com a correção para LOG_LEVEL_CONFIG_ATUAL e as extrações de JSON ajustadas)
    AMBIENTE_ATUAL = "PRODUCAO" 
    # AMBIENTE_ATUAL = "SANDBOX"
    
    LOG_LEVEL_CONFIG_ATUAL = LOG_LEVEL_GLOBAL 
    
    for handler in logging.root.handlers[:]: logging.root.removeHandler(handler) 
    logging.basicConfig(level=LOG_LEVEL_CONFIG_ATUAL, format=log_format, force=True)

    logging.info(f"Executando script em: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    logging.info(f"Ambiente: {AMBIENTE_ATUAL}, Nível de Log Efetivo: {logging.getLevelName(logging.getLogger().getEffectiveLevel())}")

    if AMBIENTE_ATUAL == "PRODUCAO":
        TOKEN_URL, API_BASE_URL, CLIENT_ID, CLIENT_SECRET, X_APP_KEY, CERT_PATH, VERIFY_SSL = \
        TOKEN_URL_PRODUCAO, PAYMENT_RECEIPTS_API_PRODUCAO_BASE, CLIENT_ID_PRODUCAO, \
        CLIENT_SECRET_PRODUCAO, X_APP_KEY_PRODUCAO, CAMINHO_CERTIFICADO_PRODUCAO_PEM, VERIFICAR_SSL_PRODUCAO
        logging.warning("--- EXECUTANDO EM AMBIENTE DE PRODUÇÃO ---")
    else: 
        TOKEN_URL, API_BASE_URL, CLIENT_ID, CLIENT_SECRET, X_APP_KEY, CERT_PATH, VERIFY_SSL = \
        TOKEN_URL_SANDBOX, PAYMENT_RECEIPTS_API_SANDBOX_BASE, CLIENT_ID_SANDBOX, \
        CLIENT_SECRET_SANDBOX, X_APP_KEY_SANDBOX, CAMINHO_CERTIFICADO_SANDBOX_PEM, VERIFICAR_SSL_SANDBOX
    
    api_session = requests.Session()
    # O certificado e verify são passados por chamada agora no make_api_request,
    # mas o AuthManager pode ter sua própria config para o token.
    
    auth_manager = SantanderAuthManager(
        client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
        token_url=TOKEN_URL, cert_path=CERT_PATH, 
        verify_ssl=VERIFY_SSL, session=api_session # Passa a mesma sessão para o token
    )
    
    token_inicial = auth_manager.get_access_token()

    if token_inicial:
        logging.info(f"\n--- Iniciando Processo de Comprovantes ({AMBIENTE_ATUAL}) ---")
        data_hoje = datetime.now() - timedelta(days=1) # Caso queira usar a data de hoje, usar days=0
        data_consulta_str = data_hoje.strftime('%Y-%m-%d')
        # data_consulta_str = "2025-05-15" # Para usar a data dos seus exemplos Postman bem sucedidos
        
        logging.info(f"Buscando comprovantes para start_date: {data_consulta_str}, end_date: {data_consulta_str}")
        resp_lista = listar_comprovantes_pagamento(api_session, auth_manager, X_APP_KEY, API_BASE_URL, data_consulta_str, data_consulta_str, limit=5)

        if resp_lista and resp_lista.get("status_code") == 200:
            dados_lista = resp_lista.get("data", {}); 
            lista_comprovantes = dados_lista.get('paymentsReceipts') 
            if not isinstance(lista_comprovantes, list) and isinstance(dados_lista, dict): 
                for key_fb in ['_content', 'data', 'items', 'receipts']: 
                    if key_fb in dados_lista and isinstance(dados_lista[key_fb], list): lista_comprovantes = dados_lista[key_fb]; break
            
            if isinstance(lista_comprovantes, list):
                if not lista_comprovantes: logging.info("Nenhum comprovante encontrado para os critérios.")
                else:
                    logging.info(f"Encontrados {len(lista_comprovantes)} comprovantes. Processando...")
                    sucessos_download = 0; falhas_processamento = 0
                    for i, item in enumerate(lista_comprovantes):
                        logging.info(f"\n{'-'*20} Comprovante #{i+1} de {len(lista_comprovantes)} {'-'*20}")
                        payment_id = item.get('payment', {}).get('paymentId')
                        if not payment_id: logging.warning(f"PULANDO: 'payment.paymentId' não encontrado."); falhas_processamento+=1; continue
                        logging.info(f"Trabalhando com paymentId: {payment_id}")
                        
                        req_id_final = None; pdf_baixado_com_sucesso = False; tentar_download_final = False
                        
                        logging.info("\n--- Etapa 1: Criar/Verificar Solicitação ---")
                        resp_criacao = criar_solicitacao_arquivo_comprovante(api_session, auth_manager, X_APP_KEY, API_BASE_URL, payment_id, {})
                        
                        if resp_criacao.get("error_code") == "006": 
                            logging.info(f"INFO: Erro 006 ('Já existe') para {payment_id}. Buscando histórico...")
                            resp_hist = listar_solicitacoes_de_arquivo_por_comprovante(api_session, auth_manager, X_APP_KEY, API_BASE_URL, payment_id)
                            if resp_hist and resp_hist.get("status_code") == 200:
                                dados_hist = resp_hist.get("data", {}); lista_hist = None
                                key_hist_list = 'paymentReceiptsFileRequests' 
                                if key_hist_list in dados_hist and isinstance(dados_hist[key_hist_list], list):
                                    lista_hist = dados_hist[key_hist_list]
                                else:
                                    for key_fb_hist in ['fileRequestsList','fileRequests','_content','data']: 
                                        if key_fb_hist in dados_hist and isinstance(dados_hist[key_fb_hist], list): lista_hist = dados_hist[key_fb_hist]; break
                                
                                if isinstance(lista_hist, list) and lista_hist:
                                    logging.info(f"Encontradas {len(lista_hist)} solicitações no histórico para {payment_id}.")
                                    for req_hist_item in lista_hist:
                                        rid_hist = req_hist_item.get('request',{}).get('requestId')
                                        stat_obj = req_hist_item.get('file',{}).get('statusInfo',{}) 
                                        stat_hist = stat_obj.get('statusCode','UNKNOWN').upper()
                                        logging.info(f"  - Histórico: ReqId={rid_hist}, Status={stat_hist}")
                                        if rid_hist and stat_hist in ["AVAILABLE","COMPLETED", "VÁLIDO", "SUCESSO"]: 
                                            req_id_final = rid_hist; tentar_download_final = True; break 
                                    if not req_id_final and lista_hist: 
                                        for req_hist_item in lista_hist:
                                           rid_hist = req_hist_item.get('request',{}).get('requestId')
                                           stat_obj = req_hist_item.get('file',{}).get('statusInfo',{}) 
                                           stat_hist = stat_obj.get('statusCode','UNKNOWN').upper()
                                           if rid_hist and stat_hist not in ["ERROR", "EXPURGED", "FAILED", "EXPURGADO", "ERRO"]: 
                                               req_id_final = rid_hist; tentar_download_final = True; break
                                    if req_id_final: logging.info(f"  >> Usando requestId '{req_id_final}' do histórico.")
                                    else: logging.warning("Nenhum requestId utilizável encontrado no histórico.")
                                else: logging.warning(f"Histórico para {payment_id} vazio ou formato inesperado.")
                            elif resp_hist and resp_hist.get("error_code") == "007": 
                                logging.error(f"ERRO: Listar histórico para {payment_id} falhou com erro 007 ('Cód. requisição não localizado').")
                            else: logging.error(f"Falha ao buscar histórico para {payment_id}. Resposta: {resp_hist}")
                        
                        elif resp_criacao.get("error_code") == "007":
                             logging.error(f"ERRO: API retornou erro 007 ao CRIAR solicitação para PID {payment_id}. Este paymentId pode ser inválido.")
                        
                        elif resp_criacao.get("status_code") and str(resp_criacao.get("status_code")).startswith("2"): 
                            dados_api_criacao = resp_criacao.get("data", {})
                            req_obj_criacao = dados_api_criacao.get("request", {})
                            req_id_final = req_obj_criacao.get("requestId") 

                            if req_id_final:
                                logging.info(f"Nova solicitação criada com requestId: {req_id_final}")
                                status_info_criacao = dados_api_criacao.get("file", {}).get("statusInfo", {})
                                status_req_criacao = status_info_criacao.get("statusCode", "UNKNOWN").upper()
                                logging.info(f"Status inicial da nova solicitação: {status_req_criacao}")
                                tentar_download_final = True 
                                if status_req_criacao in ["REQUESTED", "PROCESSING", "EM_PROCESSAMENTO"]:
                                    logging.info("Aguardando processamento inicial do arquivo (15s)..."); time.sleep(15) 
                                elif status_req_criacao == "AVAILABLE":
                                     logging.info("Status inicial 'AVAILABLE'. O fluxo de download tentará obter o link.")
                            else: 
                                logging.error(f"ERRO: Solicitação criada (status {resp_criacao.get('status_code')}), mas 'requestId' não encontrado em 'response.data.request.requestId'.")
                                logging.debug(f"Resposta completa da criação para depuração: {json.dumps(dados_api_criacao, indent=2)}")
                        else: 
                            logging.error(f"Falha crítica ao criar solicitação para {payment_id}. Resposta: {resp_criacao}")

                        # Etapa 2: Obter status e Baixar
                        if req_id_final and tentar_download_final:
                            logging.info(f"\n--- Etapa 2: Obter status/baixar para requestId: {req_id_final} ---")
                            max_tentativas_status_dl = 3; delay_status_dl = 10
                            for tentativa_s_dl in range(max_tentativas_status_dl):
                                logging.info(f"Tentativa de status/download {tentativa_s_dl + 1}/{max_tentativas_status_dl}...")
                                resp_get_status = obter_status_solicitacao_arquivo(api_session, auth_manager, X_APP_KEY, API_BASE_URL, payment_id, req_id_final)
                                
                                if resp_get_status and resp_get_status.get("status_code") == 200 and resp_get_status.get("is_json"):
                                    dados_status = resp_get_status.get("data", {})
                                    status_atual_info = dados_status.get('file', {}).get('statusInfo', {})
                                    status_atual = status_atual_info.get('statusCode', 'UNKNOWN').upper()
                                    logging.info(f"  Status atual no JSON: {status_atual}")

                                    if status_atual == "AVAILABLE": 
                                        link_dl = dados_status.get('file', {}).get('fileRepository', {}).get('location')
                                        if link_dl:
                                            logging.info(f"Status AVAILABLE. Tentando baixar do link: {link_dl}")
                                            safe_pid = payment_id.replace('/','_').replace('\\','_').replace(':','_')
                                            safe_rid = req_id_final.replace('/','_').replace('\\','_').replace(':','_')
                                            fpath_dl = os.path.join(PASTA_DOWNLOAD_COMPROVANTES, f"{safe_pid}.pdf")
                                            if baixar_pdf_do_link(api_session, link_dl, fpath_dl, auth_manager.get_ssl_verify_option()): 
                                                 logging.info(f"DOWNLOAD DO LINK CONCLUÍDO para {payment_id}.")
                                                 pdf_baixado_com_sucesso = True
                                            else: logging.error(f"Falha ao baixar PDF do link para {payment_id}.")
                                            break 
                                        else: logging.error("ERRO: Status AVAILABLE mas link ('location') não encontrado."); break
                                    elif status_atual in ["REQUESTED", "PROCESSING", "EM_PROCESSAMENTO"]:
                                        if tentativa_s_dl < max_tentativas_status_dl - 1: 
                                            logging.info(f"  Arquivo '{status_atual}'. Aguardando {delay_status_dl}s...")
                                            time.sleep(delay_status_dl)
                                        else: logging.warning(f"  Tempo máximo de espera. Último status: {status_atual}."); break
                                    else: logging.warning(f"  Status final ('{status_atual}') não permite download."); break
                                else: 
                                    logging.error(f"Falha obter status JSON para ReqId {req_id_final} (Status: {resp_get_status.get('status_code')}). Resposta: {resp_get_status.get('data')}")
                                    break 
                            
                            if not pdf_baixado_com_sucesso: falhas_processamento += 1
                            else: sucessos_download += 1
                        elif not req_id_final: 
                            logging.warning(f"Não foi possível determinar 'requestId' para {payment_id}.")
                            falhas_processamento += 1
                        elif req_id_final and not tentar_download_final: 
                             logging.info(f"Download não tentado para requestId {req_id_final}.")
                             falhas_processamento +=1
                        logging.info(f"--- Fim do Comprovante #{i+1} ---")
                # Fim do for item
                    logging.info(f"\nProcessamento geral. Downloads: {sucessos_download}. Falhas: {falhas_processamento}.")
            else: 
                 logging.error("Resposta da lista de comprovantes não continha uma lista válida.")
                 if resp_lista and resp_lista.get("data") is not None:
                    logging.error(f"Estrutura de 'data' recebida: {json.dumps(resp_lista.get('data'), indent=2)}")
        else: 
            logging.error("\nFalha ao listar comprovantes (chamada inicial).")
            if resp_lista: logging.error(f"Detalhes da falha: Status {resp_lista.get('status_code')}, Data: {resp_lista.get('data')}")
    else: 
        logging.critical("\nFalha ao obter token. Fim da execução.")