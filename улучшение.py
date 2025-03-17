from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.lang import Builder
from kivy.clock import Clock
from kivy.properties import BooleanProperty, StringProperty
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.core.clipboard import Clipboard
from kivy.metrics import dp
from plyer import filechooser
import base64
import os
import json
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import pyotp
import qrcode

# Конфигурация
SALT_LENGTH = 16
IV_LENGTH = 12
ITERATIONS = 600000
KEY_LENGTH = 32
CHUNK_SIZE = 1024 * 1024  # 1MB
MASTER_PASSWORD = "2023"
METADATA_SEPARATOR = b'\x00'

Builder.load_string('''
<LoginScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: dp(20)
        spacing: dp(15)
        
        TextInput:
            id: password_input
            hint_text: 'Введите мастер-пароль'
            password: True
            size_hint_y: None
            height: dp(50)
            
        Label:
            id: error_label
            color: 1, 0, 0, 1
            size_hint_y: None
            height: dp(30)
            
        Button:
            text: 'Войти'
            background_color: 0, 0.7, 0, 1
            size_hint_y: None
            height: dp(60)
            on_press: root.check_password()

<CryptoScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: dp(10)
        spacing: dp(10)
        
        BoxLayout:
            size_hint_y: None
            height: dp(50)
            spacing: dp(5)
            
            Button:
                id: mode_btn
                text: root.mode_text
                on_press: root.toggle_mode()
                
            Button:
                id: totp_btn
                text: root.totp_status
                on_press: root.toggle_2fa()
        
        ScrollView:
            TextInput:
                id: text_input
                hint_text: 'Введите текст или выберите файл...'
                size_hint_y: None
                height: max(self.minimum_height, dp(200))
                
        TextInput:
            id: password_input
            hint_text: 'Пароль шифрования'
            password: True
            size_hint_y: None
            height: dp(50)
            
        TextInput:
            id: totp_input
            hint_text: 'Код 2FA (если требуется)'
            size_hint_y: None
            height: dp(50)
            input_filter: 'int'
            multiline: False
        
        BoxLayout:
            size_hint_y: None
            height: dp(60)
            spacing: dp(5)
            
            Button:
                text: '📁 Файл'
                on_press: root.show_file_chooser()
                
            Button:
                id: execute_btn
                text: '🔒 Выполнить'
                on_press: root.start_operation()
                disabled: False
                
            Button:
                text: '📋 Копировать'
                on_press: root.copy_text()
        
        ProgressBar:
            id: progress_bar
            size_hint_y: None
            height: dp(20)
            
        Label:
            id: status_label
            text: 'Готово'
            size_hint_y: None
            height: dp(30)
''')

class LoginScreen(Screen):
    def check_password(self):
        if self.ids.password_input.text == MASTER_PASSWORD:
            self.manager.current = 'crypto'
        else:
            self.ids.error_label.text = "Неверный пароль!"
            self.ids.password_input.text = ""

class CryptoScreen(Screen):
    encrypt_mode = BooleanProperty(True)
    totp_enabled = BooleanProperty(False)
    mode_text = StringProperty("Шифровать")
    totp_status = StringProperty("2FA: Выкл")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.config = self.load_config()
        self.current_file = None
        self.totp_secret = self.config.get("totp_secret")
        self.totp_enabled = self.config.get("totp_enabled", False)
        self.update_ui()

    def load_config(self):
        try:
            if os.path.exists("config.json"):
                with open("config.json", "r") as f:
                    return json.load(f)
        except Exception as e:
            print(f"Ошибка загрузки конфига: {e}")
        return {"totp_enabled": False, "totp_secret": None}

    def save_config(self):
        try:
            with open("config.json", "w") as f:
                json.dump({
                    "totp_enabled": self.totp_enabled,
                    "totp_secret": self.totp_secret
                }, f)
        except Exception as e:
            print(f"Ошибка сохранения конфига: {e}")

    def update_ui(self):
        self.mode_text = "Шифровать" if self.encrypt_mode else "Дешифровать"
        self.totp_status = f"2FA: {'Вкл' if self.totp_enabled else 'Выкл'}"
        self.ids.totp_input.disabled = not self.totp_enabled

    def toggle_mode(self):
        self.encrypt_mode = not self.encrypt_mode
        self.ids.text_input.text = ""
        self.current_file = None
        self.update_ui()

    def show_file_chooser(self):
        try:
            filechooser.open_file(on_selection=self.handle_file_selection)
        except Exception as e:
            self.show_error(f"Ошибка выбора файла: {str(e)}")

    def handle_file_selection(self, selection):
        if selection:
            self.current_file = selection[0]
            self.ids.text_input.text = os.path.basename(self.current_file)

    def start_operation(self):
        """Проверяет 2FA перед запуском операции шифрования"""
        if self.totp_enabled:
            if not self.verify_2fa(self.totp_secret):  # Передаем текущий секрет
                self.show_error("Неверный код 2FA")
                return

        self.disable_execute_button()
        threading.Thread(target=self.process_operation).start()

    def verify_2fa(self, secret):
        """Проверяет код 2FA с указанным секретом"""
        if not secret:
            return False
        
        try:
            code = self.ids.totp_input.text
            if not code.isdigit() or len(code) != 6:
                return False
            return pyotp.TOTP(secret).verify(code)
        except:
            return False

    def decrypt(self, encrypted_data, password):
        self.disable_execute_button()
        threading.Thread(target=self.process_operation).start()

    def process_operation(self):
        try:
            self.update_status("Начало обработки...", 0)
            result = self.process_file() if self.current_file else self.process_text()
            self.update_status("Готово!", 100)
            self.set_text(result)
        except Exception as e:
            self.show_error(str(e))
        finally:
            self.enable_execute_button()

    def process_text(self):
        text = self.ids.text_input.text
        if self.encrypt_mode:
            return self.encrypt(text.encode(), self.ids.password_input.text)
        return self.decrypt(text, self.ids.password_input.text)

    def process_file(self):
        input_path = self.current_file
        output_path = f"{input_path}.enc" if self.encrypt_mode else f"{input_path}.dec"
        
        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            file_size = os.path.getsize(input_path)
            processed = 0
            
            for chunk in iter(lambda: fin.read(CHUNK_SIZE), b''):
                processed += len(chunk)
                self.update_status(
                    f"Обработано {processed//1048576}MB",
                    int(processed/file_size*100)
                )
                
                if self.encrypt_mode:
                    encrypted = self.encrypt(chunk, self.ids.password_input.text)
                    fout.write(base64.b64decode(encrypted))
                else:
                    decrypted = self.decrypt(base64.b64encode(chunk).decode(), self.ids.password_input.text)
                    fout.write(decrypted)
        
        return f"Файл сохранен: {output_path}"

    def encrypt(self, data, password):
        salt = os.urandom(SALT_LENGTH)
        iv = os.urandom(IV_LENGTH)
        
        # Формируем метаданные
        metadata = {
            "2fa_enabled": self.totp_enabled,
            "2fa_secret": self.totp_secret if self.totp_enabled else None
        }
        metadata_bytes = json.dumps(metadata).encode()
        full_data = metadata_bytes + METADATA_SEPARATOR + data
        
        # Шифруем
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=ITERATIONS,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(full_data) + encryptor.finalize()
        
        return base64.urlsafe_b64encode(
            salt + iv + encryptor.tag + ciphertext
        ).decode()

    def decrypt(self, encrypted_data, password):
        try:
            decoded = base64.urlsafe_b64decode(encrypted_data)
            salt = decoded[:SALT_LENGTH]
            iv = decoded[SALT_LENGTH:SALT_LENGTH+IV_LENGTH]
            tag = decoded[SALT_LENGTH+IV_LENGTH:SALT_LENGTH+IV_LENGTH+16]
            ciphertext = decoded[SALT_LENGTH+IV_LENGTH+16:]
            
            # Дешифруем данные
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=KEY_LENGTH,
                salt=salt,
                iterations=ITERATIONS,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Извлекаем метаданные
            sep_pos = decrypted.find(METADATA_SEPARATOR)
            if sep_pos == -1:
                return decrypted.decode()
            
            metadata = json.loads(decrypted[:sep_pos])
            data = decrypted[sep_pos+1:]
            
            # Проверка 2FA
            if metadata.get("2fa_enabled"):
                if not self.verify_2fa(metadata["2fa_secret"]):
                    raise ValueError("Требуется код 2FA для дешифровки")
            
            return data.decode()
        except InvalidTag:
            raise ValueError("Неверный пароль или поврежденные данные")

    def verify_2fa(self, secret):
        if not secret:
            return False
        
        try:
            code = self.ids.totp_input.text
            if not code.isdigit() or len(code) != 6:
                return False
            return pyotp.TOTP(secret).verify(code)
        except:
            return False

    def toggle_2fa(self):
        if self.totp_enabled:
            self.disable_2fa()
        else:
            self.enable_2fa()
        self.update_ui()
        self.save_config()

    def enable_2fa(self):
        """Включает 2FA, используя существующий секрет при наличии"""
        if not self.totp_secret:
            self.totp_secret = pyotp.random_base32()
            self.show_qr_code()  # Генерируем QR только при первом включении
        self.totp_enabled = True
        self.save_config()

    def disable_2fa(self):
        """Отключает 2FA без удаления секрета"""
        self.totp_enabled = False
        self.save_config()

    def show_qr_code(self):
        """Показывает существующий QR-код или создает новый"""
        if not self.totp_secret:
            return
            
        if not os.path.exists("qr.png"):
            # Генерируем QR только если файл отсутствует
            uri = pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
                name="CryptoApp",
                issuer_name="SecureApp"
            )
            qrcode.make(uri).save("qr.png")
        
        self.show_popup("Используйте ранее созданный QR-код: qr.png")

    def copy_text(self):
        Clipboard.copy(self.ids.text_input.text)
        self.update_status("Текст скопирован!", 0)

    def update_status(self, message, progress):
        Clock.schedule_once(lambda dt: self._update_status(message, progress))

    def _update_status(self, message, progress):
        self.ids.status_label.text = message
        self.ids.progress_bar.value = progress

    def set_text(self, text):
        Clock.schedule_once(lambda dt: setattr(self.ids.text_input, 'text', text))

    def enable_execute_button(self):
        Clock.schedule_once(lambda dt: setattr(self.ids.execute_btn, 'disabled', False))

    def disable_execute_button(self):
        Clock.schedule_once(lambda dt: setattr(self.ids.execute_btn, 'disabled', True))

    def show_error(self, message):
        Clock.schedule_once(lambda dt: Popup(
            title="Ошибка",
            content=Label(text=message),
            size_hint=(0.8, 0.3)
        ).open())

    def show_popup(self, message):
        Clock.schedule_once(lambda dt: Popup(
            title="Инфо",
            content=Label(text=message),
            size_hint=(0.6, 0.4)
        ).open())

class CryptoManager(ScreenManager):
    pass

class MainApp(App):
    def build(self):
        sm = CryptoManager()
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(CryptoScreen(name='crypto'))
        return sm

if __name__ == "__main__":
    MainApp().run()