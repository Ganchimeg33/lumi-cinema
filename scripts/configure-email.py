from pathlib import Path
from getpass import getpass
import re,json,os
p=Path('.env')
if not Path('server.mjs').exists():
    raise SystemExit('Run from the lumi-cinema project folder.')
print('Gmail sender setup. Your normal Gmail password is NOT used.')
email=input('Sender Gmail address: ').strip().lower()
if not re.fullmatch(r'[a-z0-9][a-z0-9._%+-]*@gmail\.com',email):
    raise SystemExit('Enter a valid @gmail.com address.')
password=getpass('Google App Password (hidden): ').replace(' ','')
if len(password)!=16 or not password.isascii() or not password.isalnum():
    raise SystemExit('Enter the 16-character Google App Password.')
values={'SMTP_HOST':'smtp.gmail.com','SMTP_PORT':'465','SMTP_USER':email,'SMTP_PASS':password,'MAIL_FROM':email}
old=p.read_text() if p.exists() else ''
lines=[line for line in old.splitlines() if line.split('=',1)[0].strip() not in values]
lines.extend(k+'='+json.dumps(v) for k,v in values.items())
p.write_text('\n'.join(lines)+'\n')
os.chmod(p,0o600)
print('Sender settings saved in .env. Restart npm start. Do not share .env.')
