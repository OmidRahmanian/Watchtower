import os
import requests
msg = f"========== ***New HTTP Service test*** ===========\n"
msg += ">>> Subdomain : "
msg += f"""```python
test```"""
msg += "Status Code : "
msg += f"""```php
test```"""
msg += "Title : "
msg += f"""```
test```"""
msg += "Tech : "
msg += f"""```
test```"""
msg += "Date : "
msg += f"""```
1403-10-10```"""


# TODO: Add your Telegram bot token and chat ID as environment variables before running.
telegram_token = os.environ["OTHER_TELEGRAM_TOKEN"]
telegram_chat_id = os.environ["TELEGRAM_CHAT_ID"]
requests.get(f"https://api.telegram.org/bot{telegram_token}/sendMessage?chat_id={telegram_chat_id}&text={msg}&parse_mode=MarkDown")
