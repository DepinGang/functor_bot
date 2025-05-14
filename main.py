import asyncio
import json
import time
import base64
import os
import random
import pytz
import requests
import imaplib
import email
import re
from datetime import datetime, timedelta
from aiohttp import ClientResponseError, ClientSession, ClientTimeout
from fake_useragent import FakeUserAgent
from colorama import Fore, Style
from cryptography.fernet import Fernet
from typing import Optional, List, Dict, Tuple
from config import BASE_URL, INVITE_CODE, HEADERS, EMAIL_SENDER, IMAP_SERVER, IMAP_PORT

utc = pytz.UTC
ua = FakeUserAgent()

class Functor:
    def __init__(self):
        self.headers = HEADERS
        self.proxies = self.read_proxies('proxies.txt')
        self.invite_code = INVITE_CODE
        self.base_url = BASE_URL
        self.email_sender = EMAIL_SENDER
        self.imap_server = IMAP_SERVER
        self.imap_port = IMAP_PORT
        self.encrypted_license_key = "Z0FBQUFBQm9KTm91WEpTaW9mVW14UlVpNVdBZTBLVlc2bFcxNlBScUU5MVd5Y1BQYm5OZ1JGcXZWT3E2aXAxRmtyb2UyYWhndTVUaHlhV0tlSFE4TklHb21lRm40QjhGXy1KdnBhVy1YeHJBQThRbmV0MHBzRFE9"
        self.fernet_key = "Mjx7q0XQd-m5WZxcAwoe9euwuora__n2HdhdAMLLVpM="

    def verify_license(self):
        """Проверяет лицензионный ключ при первом запуске с помощью Fernet."""
        flag_file = "license_verified.flag"
        
        # Проверяем, существует ли флаг верификации
        if os.path.exists(flag_file):
            self.log(f"{Fore.GREEN}Лицензия уже проверена. Продолжаем...{Style.RESET_ALL}")
            return True

        # Расшифровываем лицензионный ключ
        try:
            fernet = Fernet(self.fernet_key.encode('utf-8'))
            decoded_key = fernet.decrypt(base64.b64decode(self.encrypted_license_key)).decode('utf-8')
        except Exception as e:
            self.log(f"{Fore.RED}Ошибка расшифровки лицензионного ключа: {e}{Style.RESET_ALL}")
            return False

        # Запрашиваем ключ у пользователя
        user_key = input(f"{Fore.CYAN + Style.BRIGHT}Введите лицензионный ключ (XXXX-XXXX-XXXX-XXXX): {Style.RESET_ALL}").strip().upper()
        if not user_key:
            self.log(f"{Fore.RED}Ключ не введен! Для получения ключа (бесплатно) перейдите в чат https://t.me/depingangchannel{Style.RESET_ALL}")
            return False
        if user_key == decoded_key:
            self.log(f"{Fore.GREEN}Лицензионный ключ верный! Продолжаем...{Style.RESET_ALL}")
            # Создаем флаг верификации
            try:
                with open(flag_file, 'w') as f:
                    f.write("License verified")
                return True
            except Exception as e:
                self.log(f"{Fore.RED}Ошибка создания флага верификации: {e}{Style.RESET_ALL}")
                return False
        else:
            self.log(f"{Fore.RED}Неверный лицензионный ключ! Для получения ключа перейдите в чат https://t.me/depingangchannel{Style.RESET_ALL}")
            return False

    def read_proxies(self, file_path: str) -> List[Dict[str, str]]:
        """Читает прокси из файла в формате username:password@host:port."""
        proxies = []
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                for line in file:
                    line = line.strip()
                    if not line or '@' not in line or ':' not in line:
                        self.log(f"{Fore.RED}Пропущена строка прокси: {line} (неверный формат){Style.RESET_ALL}")
                        continue
                    auth, host_port = line.split('@', 1)
                    username, password = auth.split(':', 1)
                    host, port = host_port.split(':', 1)
                    proxy = {
                        "http": f"http://{username}:{password}@{host}:{port}",
                        "https": f"http://{username}:{password}@{host}:{port}"
                    }
                    proxies.append(proxy)
            return proxies
        except FileNotFoundError:
            self.log(f"{Fore.RED}Файл {file_path} не найден.{Style.RESET_ALL}")
            return []
        except Exception as e:
            self.log(f"{Fore.RED}Ошибка при чтении файла {file_path}: {e}{Style.RESET_ALL}")
            return []

    def read_credentials(self, file_path: str) -> List[Tuple[str, str]]:
        """Читает email и пароль из файла в формате email:password."""
        credentials = []
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                for line in file:
                    line = line.strip()
                    if not line or ':' not in line:
                        self.log(f"{Fore.RED}Пропущена строка: {line} (неверный формат){Style.RESET_ALL}")
                        continue
                    parts = line.split(':')
                    if len(parts) != 2:
                        self.log(f"{Fore.RED}Неверный формат строки: {line} (ожидается email:password){Style.RESET_ALL}")
                        continue
                    email, password = parts[0].strip(), parts[1].strip()
                    credentials.append((email, password))
            return credentials
        except FileNotFoundError:
            self.log(f"{Fore.RED}Файл {file_path} не найден.{Style.RESET_ALL}")
            return []
        except Exception as e:
            self.log(f"{Fore.RED}Ошибка при чтении файла {file_path}: {e}{Style.RESET_ALL}")
            return []

    def save_success_account(self, email: str, account_pass: str, file_path: str = "success_reg.txt"):
        """Записывает успешно зарегистрированный аккаунт в файл."""
        try:
            with open(file_path, 'a', encoding='utf-8') as file:
                file.write(f"{email}:{account_pass}\n")
            self.log(f"{Fore.GREEN}Аккаунт {self.mask_account(email)} сохранён в {file_path}{Style.RESET_ALL}")
        except Exception as e:
            self.log(f"{Fore.RED}Ошибка при записи аккаунта {self.mask_account(email)} в {file_path}: {e}{Style.RESET_ALL}")

    def check_email_exists(self, email: str, proxies: Dict[str, str]) -> bool:
        """Проверяет, существует ли email."""
        url = f"{self.base_url}/auth/check-exist-email"
        payload = {"email": email}
        headers = {**self.headers, "User-Agent": ua.random}
        try:
            response = requests.post(url, headers=headers, json=payload, proxies=proxies, timeout=10)
            response.raise_for_status()
            return response.text == "false"  # Если false, email свободен
        except requests.RequestException as e:
            self.log(f"{Fore.RED}Ошибка при проверке email {self.mask_account(email)}: {e}{Style.RESET_ALL}")
            return False

    def validate_invite_code(self, invite_code: str, proxies: Dict[str, str]) -> bool:
        """Проверяет валидность инвайт-кода."""
        url = f"{self.base_url}/invitation-code/validate/{invite_code}"
        headers = {**self.headers, "User-Agent": ua.random}
        try:
            response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
            response.raise_for_status()
            return response.status_code == 200
        except requests.RequestException as e:
            self.log(f"{Fore.RED}Ошибка при валидации инвайт-кода: {e}{Style.RESET_ALL}")
            return False

    def register_account(self, email: str, password: str, invite_code: str, proxies: Dict[str, str]) -> Optional[Dict]:
        """Регистрирует аккаунт."""
        url = f"{self.base_url}/auth/signup-user"
        payload = {
            "email": email,
            "password": password,
            "acceptTermsAndConditions": True,
            "authType": "otp",
            "from": "extension",
            "invitationCode": invite_code,
            "referralCode": ""
        }
        headers = {**self.headers, "User-Agent": ua.random}
        try:
            response = requests.post(url, headers=headers, json=payload, proxies=proxies, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.log(f"{Fore.RED}Ошибка при регистрации {self.mask_account(email)}: {e}{Style.RESET_ALL}")
            try:
                self.log(f"{Fore.RED}Ответ сервера: {response.text}{Style.RESET_ALL}")
            except:
                self.log(f"{Fore.RED}Нет ответа сервера.{Style.RESET_ALL}")
            return None

    def verify_email_code(self, email: str, code: str, token: str, proxies: Dict[str, str]) -> Optional[Dict]:
        """Подтверждает код с почты."""
        url = f"{self.base_url}/auth/verify-otp-user"
        payload = {"otp": code}
        headers = {**self.headers, "Authorization": f"Bearer {token}", "User-Agent": ua.random}
        self.log(f"{Fore.CYAN}Извлечённый OTP для {self.mask_account(email)}: {code}{Style.RESET_ALL}")
        try:
            response = requests.post(url, headers=headers, json=payload, proxies=proxies, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.log(f"{Fore.RED}Ошибка при верификации на {url}: {e}{Style.RESET_ALL}")
            try:
                self.log(f"{Fore.RED}Ответ сервера: {response.text}{Style.RESET_ALL}")
            except:
                self.log(f"{Fore.RED}Нет ответа сервера.{Style.RESET_ALL}")
            return None

    def get_verification_code(self, email_addr: str, email_pass: str) -> Optional[str]:
        """Получает код верификации из письма через IMAP."""
        try:
            mail = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            mail.login(email_addr, email_pass)
            folders = ["INBOX", "Spam", "Junk", "Trash"]
            for attempt in range(2):
                for folder in folders:
                    try:
                        mail.select(folder)
                    except imaplib.IMAP4.error:
                        self.log(f"{Fore.RED}Папка {folder} не найдена.{Style.RESET_ALL}")
                        continue
                    _, message_numbers = mail.search(None, f'FROM "{self.email_sender}"')
                    latest_email_id = message_numbers[0].split()[-1] if message_numbers[0] else None

                    if latest_email_id:
                        _, msg_data = mail.fetch(latest_email_id, "(RFC822)")
                        email_body = msg_data[0][1]
                        msg = email.message_from_bytes(email_body)
                        for part in msg.walk():
                            if part.get_content_type() == "text/html":
                                payload = part.get_payload(decode=True).decode()
                                patterns = [
                                    r'<div class="code">(\d+)</div>',
                                    r'<span class="code">(\d+)</span>',
                                    r'(\d{6})'
                                ]
                                for pattern in patterns:
                                    match = re.search(pattern, payload)
                                    if match:
                                        code = match.group(1)
                                        mail.logout()
                                        return code
                                self.log(f"{Fore.RED}Код не найден в письме из папки {folder}. Содержимое письма:{Style.RESET_ALL}")
                                self.log(f"{Fore.RED}{payload[:500]}{Style.RESET_ALL}")
                                break
                if attempt == 0:
                    self.log(f"{Fore.YELLOW}Письмо не найдено, повторная попытка через 10 секунд...{Style.RESET_ALL}")
                    time.sleep(10)

            self.log(f"{Fore.RED}Письмо от {self.email_sender} не найдено в папках {folders}.{Style.RESET_ALL}")
            _, folder_list = mail.list()
            self.log(f"{Fore.CYAN}Доступные папки в почте:{Style.RESET_ALL}")
            for folder in folder_list:
                self.log(f"{Fore.CYAN}{folder.decode()}{Style.RESET_ALL}")
            mail.logout()
            return None

        except Exception as e:
            self.log(f"{Fore.RED}Ошибка при получении кода для {self.mask_account(email_addr)}: {e}{Style.RESET_ALL}")
            return None

    async def process_account(self, email: str, account_pass: str, proxies_list: List[Dict[str, str]]):
        """Обрабатывает регистрацию и подтверждение одного аккаунта."""
        self.log(f"{Fore.CYAN}Обработка аккаунта: {self.mask_account(email)}{Style.RESET_ALL}")
        proxies = random.choice(proxies_list) if proxies_list else {}
        self.log(f"{Fore.YELLOW}Используемый прокси: {proxies.get('http', 'Без прокси')}{Style.RESET_ALL}")

        self.log(f"{Fore.CYAN}Проверка email...{Style.RESET_ALL}")
        if not self.check_email_exists(email, proxies):
            self.log(f"{Fore.RED}Email {self.mask_account(email)} уже занят или произошла ошибка.{Style.RESET_ALL}")
            return
        time.sleep(random.uniform(3, 5))

        self.log(f"{Fore.CYAN}Проверка инвайт-кода...{Style.RESET_ALL}")
        if not self.validate_invite_code(self.invite_code, proxies):
            self.log(f"{Fore.RED}Недействительный инвайт-код или ошибка.{Style.RESET_ALL}")
            return
        time.sleep(random.uniform(3, 5))

        self.log(f"{Fore.CYAN}Регистрация аккаунта...{Style.RESET_ALL}")
        registration_result = self.register_account(email, account_pass, self.invite_code, proxies)
        if not registration_result:
            self.log(f"{Fore.RED}Не удалось зарегистрировать аккаунт {self.mask_account(email)}.{Style.RESET_ALL}")
            return
        token = registration_result.get("token") or registration_result.get("accessToken")
        if not token:
            self.log(f"{Fore.RED}Не удалось извлечь JWT токен для {self.mask_account(email)}.{Style.RESET_ALL}")
            return
        time.sleep(random.uniform(3, 5))

        self.log(f"{Fore.CYAN}Получение кода верификации для {self.mask_account(email)}...{Style.RESET_ALL}")
        verification_code = self.get_verification_code(email, account_pass)
        if not verification_code:
            self.log(f"{Fore.RED}Не удалось получить код верификации для {self.mask_account(email)}.{Style.RESET_ALL}")
            return
        time.sleep(random.uniform(3, 5))

        self.log(f"{Fore.CYAN}Подтверждение кода для {self.mask_account(email)}...{Style.RESET_ALL}")
        verification_result = self.verify_email_code(email, verification_code, token, proxies)
        if verification_result and verification_result.get("verified"):
            self.log(f"{Fore.GREEN}Аккаунт {self.mask_account(email)} успешно подтвержден!{Style.RESET_ALL}")
            self.save_success_account(email, account_pass)
        else:
            self.log(f"{Fore.RED}Ошибка подтверждения кода для {self.mask_account(email)}.{Style.RESET_ALL}")

    def clear_terminal(self):
        """Очищает экран терминала."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def log(self, message):
        """Логирует сообщение с временной меткой."""
        print(
            f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now(utc).strftime('%x %X UTC')} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}{message}",
            flush=True
        )

    def welcome(self):
        """Отображает ASCII-логотип и приветственное сообщение."""
        logo = f"""
        {Fore.GREEN + Style.BRIGHT}
        $$$$$$$\  $$$$$$$$\ $$$$$$$\  $$$$$$\ $$\   $$\        $$$$$$\   $$$$$$\  $$\   $$\  $$$$$$\  
        $$  __$$\ $$  _____|$$  __$$\ \_$$  _|$$$\  $$ |      $$  __$$\ $$  __$$\ $$$\  $$ |$$  __$$\ 
        $$ |  $$ |$$ |      $$ |  $$ |  $$ |  $$$$\ $$ |      $$ /  \__|$$ /  $$ |$$$$\ $$ |$$ /  \__|
        $$ |  $$ |$$$$$\    $$$$$$$  |  $$ |  $$ $$\$$ |      $$ |$$$$\ $$$$$$$$ |$$ $$\$$ |$$ |$$$$\ 
        $$ |  $$ |$$  __|   $$  ____/   $$ |  $$ \$$$$ |      $$ |\_$$ |$$  __$$ |$$ \$$$$ |$$ |\_$$ |
        $$ |  $$ |$$ |      $$ |        $$ |  $$ |\$$$ |      $$ |  $$ |$$ |  $$ |$$ |\$$$ |$$ |  $$ |
        $$$$$$$  |$$$$$$$$\ $$ |      $$$$$$\ $$ | \$$ |      \$$$$$$  |$$ |  $$ |$$ | \$$ |\$$$$$$  |
        \_______/ \________|\__|      \______|\__|  \__|       \______/ \__|  \__|\__|  \__| \______/
                                      
                                Functor Bot by DEPIN & GANG
        {Fore.YELLOW + Style.BRIGHT}Получить лицензию: https://t.me/depingangchannel{Style.RESET_ALL}
        """
        print(logo)

    def format_seconds(self, seconds):
        """Форматирует секунды в формат ЧЧ:ММ:СС."""
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"

    def mask_account(self, account):
        """Маскирует email или токен для отображения."""
        if '@' in account:
            local, domain = account.split('@', 1)
            mask_account = local[:3] + '*' * 3 + local[-3:]
            return f"{mask_account}@{domain}"
        mask_account = account[:6] + '*' * 7 + account[-6:]
        return mask_account

    def decode_account(self, account: str):
        """Декодирует JWT-токен для получения имени пользователя, ID и времени истечения."""
        try:
            header, payload, signature = account.split(".")
            decoded_payload = base64.urlsafe_b64decode(payload + "==").decode("utf-8")
            parsed_payload = json.loads(decoded_payload)
            username = parsed_payload['email']
            user_id = parsed_payload['sub']
            exp_time_utc = parsed_payload['exp']
            return username, user_id, exp_time_utc
        except Exception as e:
            self.log(f"{Fore.RED}Ошибка декодирования токена: {e}{Style.RESET_ALL}")
            return None, None, None

    def print_account_username(self, account: str):
        """Выводит замаскированное имя пользователя."""
        separator = "=" * 25
        self.log(
            f"{Fore.CYAN + Style.BRIGHT}{separator}[{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} {self.mask_account(account)} {Style.RESET_ALL}"
            f"{Fore.CYAN + Style.BRIGHT}]{separator}{Style.RESET_ALL}"
        )

    def print_token_status(self, utc_time_now: int, exp_time_utc: int, exp_time_str: str):
        """Выводит статус токена."""
        if utc_time_now > exp_time_utc:
            return self.log(
                f"{Fore.CYAN + Style.BRIGHT}Токен   :{Style.RESET_ALL}"
                f"{Fore.RED + Style.BRIGHT} Истёк {Style.RESET_ALL}"
            )
        return self.log(
            f"{Fore.CYAN + Style.BRIGHT}Токен   :{Style.RESET_ALL}"
            f"{Fore.GREEN + Style.BRIGHT} Активен {Style.RESET_ALL}"
            f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
            f"{Fore.CYAN + Style.BRIGHT} Истекает {Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT}{exp_time_str}{Style.RESET_ALL}"
        )

    async def user_login(self, email: str, password: str, proxy: str = None, retries=5):
        """Выполняет вход пользователя и возвращает токен доступа."""
        url = f'{self.base_url}/auth/signin-user'
        data = json.dumps({'email': email, 'password': password})
        headers = {
            **self.headers,
            'Content-Length': str(len(data)),
            'Content-Type': 'application/json',
            'User-Agent': ua.random
        }
        for attempt in range(retries):
            try:
                async with ClientSession(timeout=ClientTimeout(total=30)) as session:
                    async with session.post(url=url, headers=headers, data=data, proxy=proxy) as response:
                        response.raise_for_status()
                        result = await response.json()
                        return result['accessToken']
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    self.log(f"{Fore.YELLOW}Повторная попытка входа из-за ошибки: {e}{Style.RESET_ALL}")
                    await asyncio.sleep(5)
                    continue
                self.log(f"{Fore.RED}Не удалось войти после {retries} попыток: {e}{Style.RESET_ALL}")
                return None

    async def user_data(self, token: str, proxy: str = None, retries=5):
        """Получает данные пользователя."""
        url = f'{self.base_url}/users'
        headers = {
            **self.headers,
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'User-Agent': ua.random
        }
        for attempt in range(retries):
            try:
                async with ClientSession(timeout=ClientTimeout(total=30)) as session:
                    async with session.get(url=url, headers=headers, proxy=proxy) as response:
                        response.raise_for_status()
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    self.log(f"{Fore.YELLOW}Повторная попытка получения данных пользователя из-за ошибки: {e}{Style.RESET_ALL}")
                    await asyncio.sleep(5)
                    continue
                self.log(f"{Fore.RED}Не удалось получить данные пользователя после {retries} попыток: {e}{Style.RESET_ALL}")
                return None

    async def user_checkin(self, token: str, user_id: str, proxy: str = None, retries=5):
        """Выполняет чек-ин пользователя."""
        url = f'{self.base_url}/users/earn/{user_id}'
        headers = {
            **self.headers,
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'User-Agent': ua.random
        }
        for attempt in range(retries):
            try:
                async with ClientSession(timeout=ClientTimeout(total=30)) as session:
                    async with session.get(url=url, headers=headers, proxy=proxy) as response:
                        response.raise_for_status()
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    self.log(f"{Fore.YELLOW}Повторная попытка чек-ина из-за ошибки: {e}{Style.RESET_ALL}")
                    await asyncio.sleep(5)
                    continue
                self.log(f"{Fore.RED}Не удалось выполнить чек-ин после {retries} попыток: {e}{Style.RESET_ALL}")
                return None

    async def get_access_token(self, email: str, password: str, proxy: str = None):
        """Получает токен доступа для аккаунта."""
        if proxy:
            self.log(f"{Fore.YELLOW}Используется прокси для аккаунта: {proxy}{Style.RESET_ALL}")
        token = await self.user_login(email, password, proxy)
        if token:
            self.log(
                f"{Fore.CYAN + Style.BRIGHT}Статус  :{Style.RESET_ALL}"
                f"{Fore.GREEN + Style.BRIGHT} Вход успешен {Style.RESET_ALL}"
            )
            return token
        self.print_account_username(email)
        self.log(
            f"{Fore.CYAN + Style.BRIGHT}Статус  :{Style.RESET_ALL}"
            f"{Fore.RED + Style.BRIGHT} Вход не удался {Style.RESET_ALL}"
        )
        return None

    async def process_accounts(self, token: str, user_id: str, proxy: str = None):
        """Обрабатывает аккаунт для фарминга (чек-ин и проверка баланса)."""
        balance = "N/A"
        last_checkin = None
        checkin_success = False

        user = await self.user_data(token, proxy)
        if user:
            balance = user.get("dipTokenBalance")
            last_checkin = user.get('dipInitMineTime')

        self.log(
            f"{Fore.CYAN + Style.BRIGHT}Баланс :{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} {balance} Points {Style.RESET_ALL}"
        )

        if last_checkin is None:
            check_in = await self.user_checkin(token, user_id, proxy)
            if check_in:
                checkin_success = True
                self.log(
                    f"{Fore.CYAN + Style.BRIGHT}Чек-ин:{Style.RESET_ALL}"
                    f"{Fore.GREEN + Style.BRIGHT} Выполнен {Style.RESET_ALL}"
                    f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.CYAN + Style.BRIGHT} Награда {Style.RESET_ALL}"
                    f"{Fore.WHITE + Style.BRIGHT}{check_in['tokensToAward']} Points{Style.RESET_ALL}"
                )
            else:
                self.log(
                    f"{Fore.CYAN + Style.BRIGHT}Чек-ин:{Style.RESET_ALL}"
                    f"{Fore.RED + Style.BRIGHT} Не выполнен {Style.RESET_ALL}"
                )
        else:
            now = datetime.now(utc)
            last_checkin_utc = datetime.strptime(last_checkin, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=utc)
            next_checkin_utc = last_checkin_utc + timedelta(hours=24)
            next_checkin_str = next_checkin_utc.strftime('%x %X UTC')
            if now >= next_checkin_utc:
                check_in = await self.user_checkin(token, user_id, proxy)
                if check_in:
                    checkin_success = True
                    self.log(
                        f"{Fore.CYAN + Style.BRIGHT}Чек-ин:{Style.RESET_ALL}"
                        f"{Fore.GREEN + Style.BRIGHT} Выполнен {Style.RESET_ALL}"
                        f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                        f"{Fore.CYAN + Style.BRIGHT} Награда {Style.RESET_ALL}"
                        f"{Fore.WHITE + Style.BRIGHT}{check_in['tokensToAward']} Points{Style.RESET_ALL}"
                    )
                else:
                    self.log(
                        f"{Fore.CYAN + Style.BRIGHT}Чек-ин:{Style.RESET_ALL}"
                        f"{Fore.RED + Style.BRIGHT} Не выполнен {Style.RESET_ALL}"
                    )
            else:
                self.log(
                    f"{Fore.CYAN + Style.BRIGHT}Чек-ин:{Style.RESET_ALL}"
                    f"{Fore.YELLOW + Style.BRIGHT} Уже выполнен {Style.RESET_ALL}"
                    f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.CYAN + Style.BRIGHT} Следующий чек-ин {Style.RESET_ALL}"
                    f"{Fore.WHITE + Style.BRIGHT}{next_checkin_str}{Style.RESET_ALL}"
                )

        return balance, checkin_success

    def show_menu(self):
        """Отображает меню и возвращает выбор пользователя."""
        self.clear_terminal()
        self.welcome()
        print(f"{Fore.CYAN + Style.BRIGHT}Меню:{Style.RESET_ALL}")
        print(f"{Fore.WHITE + Style.BRIGHT}1. Регистрация аккаунтов (из email.txt){Style.RESET_ALL}")
        print(f"{Fore.WHITE + Style.BRIGHT}2. Фарминг аккаунтов (из farm.txt){Style.RESET_ALL}")
        choice = input(f"{Fore.GREEN + Style.BRIGHT}Выберите опцию (1 или 2): {Style.RESET_ALL}")
        return choice

    async def run_registration(self):
        """Выполняет регистрацию аккаунтов из email.txt."""
        credentials = self.read_credentials('email.txt')
        self.log(f"{Fore.GREEN + Style.BRIGHT}Всего записей для регистрации: {len(credentials)}{Style.RESET_ALL}")
        for email, password in credentials:
            delay = random.randint(300, 400)
            self.log(f"{Fore.YELLOW}Ожидание {delay} секунд перед регистрацией следующего аккаунта...{Style.RESET_ALL}")
            await asyncio.sleep(delay)
            await self.process_account(email, password, self.proxies)
        self.log(f"{Fore.GREEN + Style.BRIGHT}Регистрация завершена.{Style.RESET_ALL}")

    async def run_farming(self):
        """Выполняет бесконечный фарминг аккаунтов из farm.txt с чек-инами раз в 24 часа."""
        while True:
            try:
                with open('farm.txt', 'r') as file:
                    accounts = [line.strip() for line in file if line.strip()]
            except FileNotFoundError:
                self.log(f"{Fore.RED}Файл 'farm.txt' не найден.{Style.RESET_ALL}")
                return

            self.log(f"{Fore.GREEN + Style.BRIGHT}Всего аккаунтов для фарминга: {len(accounts)}{Style.RESET_ALL}")
            self.log(f"{Fore.GREEN + Style.BRIGHT}Всего прокси: {len(self.proxies)}{Style.RESET_ALL}")

            balances = []
            successful_checkins = 0

            for account in accounts:
                proxy = random.choice(self.proxies).get('http') if self.proxies else None
                if not "@" in account:
                    utc_time_now = int(time.time())
                    username, user_id, exp_time_utc = self.decode_account(account)
                    if username and user_id and exp_time_utc:
                        exp_time_str = datetime.fromtimestamp(exp_time_utc, tz=utc).strftime('%x %X UTC')
                        self.print_account_username(username)
                        self.print_token_status(utc_time_now, exp_time_utc, exp_time_str)
                        if utc_time_now > exp_time_utc:
                            continue
                        balance, checkin_success = await self.process_accounts(account, user_id, proxy)
                        if balance != "N/A":
                            balances.append(float(balance))
                        if checkin_success:
                            successful_checkins += 1
                        await asyncio.sleep(3)
                        continue

                try:
                    email, password = account.split(":")
                except ValueError:
                    self.log(f"{Fore.RED}Неверный формат аккаунта: {account}{Style.RESET_ALL}")
                    continue

                if email and password:
                    self.print_account_username(email)
                    token = await self.get_access_token(email, password, proxy)
                    if not token:
                        continue
                    username, user_id, exp_time_utc = self.decode_account(token)
                    if user_id:
                        balance, checkin_success = await self.process_accounts(token, user_id, proxy)
                        if balance != "N/A":
                            balances.append(float(balance))
                        if checkin_success:
                            successful_checkins += 1
                        await asyncio.sleep(3)

            average_balance = sum(balances) / len(balances) if balances else 0
            self.log(
                f"{Fore.CYAN + Style.BRIGHT}Средний баланс: {Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT}{average_balance:.2f} Points{Style.RESET_ALL}"
            )
            self.log(f"{Fore.GREEN + Style.BRIGHT}Фарминг цикла завершен. Ожидание 24 часов до следующего цикла...{Style.RESET_ALL}")

            # Ожидание 24 часов перед следующим циклом
            seconds = 24 * 60 * 60
            while seconds > 0:
                formatted_time = self.format_seconds(seconds)
                print(
                    f"{Fore.CYAN+Style.BRIGHT}[ Ожидание{Style.RESET_ALL}"
                    f"{Fore.WHITE+Style.BRIGHT} {formatted_time} {Style.RESET_ALL}"
                    f"{Fore.CYAN+Style.BRIGHT}... ]{Style.RESET_ALL}"
                    f"{Fore.WHITE+Style.BRIGHT} | {Style.RESET_ALL}"
                    f"{Fore.BLUE+Style.BRIGHT}Следующий цикл фарминга...{Style.RESET_ALL}",
                    end="\r"
                )
                await asyncio.sleep(1)
                seconds -= 1

    async def main(self):
        """Основная функция для отображения меню и выполнения операций."""
        try:
            # Проверяем лицензионный ключ
            if not self.verify_license():
                return
            
            while True:
                choice = self.show_menu()
                if choice == '1':
                    self.clear_terminal()
                    self.welcome()
                    self.log(f"{Fore.GREEN + Style.BRIGHT}Запуск регистрации...{Style.RESET_ALL}")
                    await self.run_registration()
                    input(f"{Fore.CYAN + Style.BRIGHT}Нажмите Enter, чтобы вернуться в меню...{Style.RESET_ALL}")
                elif choice == '2':
                    self.clear_terminal()
                    self.welcome()
                    self.log(f"{Fore.GREEN + Style.BRIGHT}Запуск фарминга...{Style.RESET_ALL}")
                    await self.run_farming()
                else:
                    self.log(f"{Fore.RED}Неверный выбор. Пожалуйста, введите 1 или 2.{Style.RESET_ALL}")
                    await asyncio.sleep(2)

        except KeyboardInterrupt:
            print(
                f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now(utc).strftime('%x %X UTC')} ]{Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}"
                f"{Fore.RED + Style.BRIGHT}[ ВЫХОД ] DEPIN GANG - Functor Bot{Style.RESET_ALL}"
            )

if __name__ == "__main__":
    bot = Functor()
    asyncio.run(bot.main())
