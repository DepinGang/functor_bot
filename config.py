# Конфигурация для скрипта

BASE_URL = "https://node.securitylabs.xyz/api/v1"
INVITE_CODE = "cm4m90eqs763ro81bdrwsehwd"
EMAIL_SENDER = "no-reply@securitylabs.xyz"
IMAP_SERVER = "imap.firstmail.ltd"
IMAP_PORT = 993

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
    "Connection": "keep-alive",
    "Host": "node.securitylabs.xyz",
    "Referer": "https://node.securitylabs.xyz/?from=extension&type=signin&referralCode=cm4m90eqs763ro81bdrwsehwd",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin"
    # User-Agent генерируется динамически через FakeUserAgent
}