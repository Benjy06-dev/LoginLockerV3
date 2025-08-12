# vitals
import os
import json
import platform
import re
import time

# for cryption
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

# Gui
import customtkinter as cutk  # noqa
from tkinter import messagebox
from PyQt5.QtWidgets import QMessageBox, QApplication
from PIL import Image
import CTkListbox

# For features
import pyperclip
import string
import secrets
from datetime import datetime
from tkinter import filedialog
import ThreadHandler


class FileSystem:
    @staticmethod
    def initialisation():
        # check for ll3 file
        if not os.path.isfile(locker_file):
            LockerMem.new_user = True
            FileSystem.create_locker_file()

        # check if file is still unencrypted
        with open(locker_file, "r") as file:
            try:
                if file.read() == "{}":
                    LockerMem.new_user = True
            except UnicodeError:
                pass

    @staticmethod
    def create_locker_file():
        with open(locker_file, "w") as file:
            file.write("{}")

    @staticmethod
    def load_locker_file() -> str:
        with open(locker_file, "r", encoding="utf-8") as lf:
            return lf.read()

    @staticmethod
    def save_locker_file(encoded_content: str):
        with open(locker_file, "w", encoding="utf-8") as lf:
            lf.write(encoded_content)

    @staticmethod
    def save_last_email_file(encoded_email: str):
        with open(last_email_file, "w", encoding="utf-8") as lef:
            lef.write(encoded_email)

    @staticmethod
    def load_last_email() -> str:
        with open(last_email_file, "r", encoding="utf-8") as lef:
            return lef.read()

    @staticmethod
    def save_salt(generated_salt: str):
        with open(salt_file, mode="w", encoding="utf-8") as salt:
            salt.write(generated_salt)

    @staticmethod
    def load_salt():
        with open(salt_file, "r", encoding="utf-8") as salt:
            return salt.read()


class cryptography_protector:
    @staticmethod
    def generate_salt():
        return Features.generate_password(length=32)


    @staticmethod
    def generate_key(seed: str, salt: str) -> bytes:
        # encode_seed
        seed = seed.encode()

        # add salt
        salt = salt.encode()  # normally, one would generate a user specific salt - but I want it to be portable

        # Key-Derivation setup
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Fernet wants 32 Byte
            salt=salt,
            iterations=390000,
        )

        # generate seed based Fernet-Key
        key = base64.urlsafe_b64encode(kdf.derive(seed))

        return key

    @staticmethod
    def encrypt(data: str, key: bytes) -> str:
        # convert to bytes
        data = data.encode()

        fernet_object = Fernet(key)
        encrypted_data = fernet_object.encrypt(data)
        return encrypted_data.decode()

    @staticmethod
    def decrypt(data: str, key: bytes) -> str:
        # convert to bytes
        data = data.encode()

        fernet_object = Fernet(key)
        decrypted_data = fernet_object.decrypt(data)

        return decrypted_data.decode()

class DictionaryHandler:
    @staticmethod
    def get_locker(seed: bytes) -> dict:
        # load encoded file
        locker = FileSystem.load_locker_file()

        # decode locker (OVERWRITE)
        # locker = Coder.decode(seed=seed, encoded_text=locker)
        locker = cryptography_protector.decrypt(data=locker, key=seed)

        # put the locker into dict (locker is stored as json file)
        locker = json.loads(locker)

        # send locker back
        return locker


class Features:
    @staticmethod
    def generate_password(length: int, punctuation_allowed=True, numbers_allowed=True, readable=False) -> str:
        # Error protection
        if length < 4:
            raise ValueError("Password can not be shorter than 4 characters!")

        # Set Characters
        characters = string.ascii_letters
        vocals = "aeiou"
        consonants = "bcdfghjklmnpqrstvwxyz"  # noqa

        # Create password
        password = [secrets.choice(string.ascii_lowercase),
                    secrets.choice(string.ascii_uppercase)]

        # Add one of every aspect (if wanted) to it to make sure at least one of each is always given
        if numbers_allowed:
            characters += string.digits
            password.append(secrets.choice(string.digits))

        if punctuation_allowed:
            characters += string.punctuation
            password.append(secrets.choice(string.punctuation))

        # generate readable password
        if readable is True:
            # shuffle it
            secrets.SystemRandom().shuffle(password)

            # generate readable password
            sub_pass = []
            for i in range(length - len(password)):
                if i % 2 == 0:
                    sub_pass.append(secrets.choice(consonants))
                else:
                    sub_pass.append(secrets.choice(vocals))

                if secrets.choice([True, False]):
                    sub_pass[-1] = sub_pass[-1].upper()
            password = sub_pass + password

        # generate any password
        elif readable is False:
            # Generate the rest of the password
            for _ in range(length - len(password)):
                password.append(secrets.choice(characters))

            # shuffle it
            secrets.SystemRandom().shuffle(password)

        return ''.join(password)

    @staticmethod
    def search_login(locker_dict: dict, key: str) -> dict:
        # Convert the search key to lowercase to perform a case-insensitive search
        key_lower = key.lower()

        # Iterate over the keys in the dictionary
        for locker_key in locker_dict.keys():
            # Convert each key to lowercase and check if it starts with the search key
            if locker_key.lower().startswith(key_lower):
                # If a match is found, return the corresponding value
                return {"name": locker_key, "email": locker_dict[locker_key][0], "password": locker_dict[locker_key][1]}

        # If no match is found, return a "Not Found" result
        return {"name": "Not Found", "email": "N/A", "password": "N/A"}

    @staticmethod
    def export_as_file(locker_dict: dict):
        # get date for file name
        date = datetime.now().strftime('%d.%m.%Y')

        # get output path
        if platform.system().lower() == "windows":
            documents_folder = os.getenv('USERPROFILE') + '\\Documents'
        else:
            documents_folder = os.getenv('HOME') + '/Documents'

        # create data string and ask for save as file
        data_string: str = ""
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"Exported Logins - {date}",
                                            filetypes=(("Json File", "*.json"), ("Text File", "*.txt")),
                                            title="Export Logins", initialdir=documents_folder)

        # abort if no path was given
        if not path:
            return

        # determine what file type user has selected
        extension = os.path.splitext(path)[1]
        match extension:
            case ".json":
                data_string = json.dumps(locker_dict, indent=4)
            case ".txt":
                data_string = f"Exported Logins {date}\nLoginLockerV3 by Benjy\n\n"
                for entry in list(locker_dict.keys()):
                    data_string += (f"\nAccount Provider: {entry}\n"
                                    f"Email/Username/Number: {locker_dict[entry][0]}\n"
                                    f"Passwort: {locker_dict[entry][1]}\n")

        # store to path
        if data_string:
            with open(path, "w", encoding="utf-8") as file:
                file.write(data_string)

    @staticmethod
    def merge_lockers(locker_dict1: dict, locker_dict2: dict) -> dict:
        # create merged dict var as dict1 copy
        merged_dict = locker_dict1.copy()

        # iterate and handle exceptions...
        for key, value in locker_dict2.items():
            if key in merged_dict:
                choice = Features.show_custom_message_box(message=f"'{key}' already exists, how would you like to "
                                                                  "proceed?", buttons=("Overwrite", "New Name",
                                                                                       "Skip", "Skip All"))
                match choice:
                    case "Overwrite":
                        merged_dict[key] = value
                    case "New Name":
                        merged_dict[f'{key}_merge_{datetime.now().strftime("%D-%H:%M:%S")}'] = value
                    case "Skip":
                        continue
                    case "Skip All":
                        return merged_dict

            else:
                merged_dict[key] = value

        return merged_dict

    @staticmethod
    def remove_from_locker(account_provider: str):
        try:
            # remove key
            del LockerMem.locker_set[account_provider]

            # Store locker to file
            # 1. encode locker
            enc_locker = cryptography_protector.encrypt(data=json.dumps(LockerMem.locker_set, indent=2),
                                                        key=LockerMem.user_seed)
            # 2. store to file
            FileSystem.save_locker_file(encoded_content=enc_locker)

        except KeyError:
            messagebox.showerror(title=appName, message=f"{account_provider} was not found!")

    @staticmethod
    def show_custom_message_box(message: str, buttons: tuple, title="Login Locker V3", width=400, height=200):
        app = QApplication([])  # noqa
        msg_box = QMessageBox()
        msg_box.setWindowTitle(title)
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setText(message)

        # Add custom buttons
        for button_text in buttons:
            msg_box.addButton(button_text, QMessageBox.YesRole)

        msg_box.setFixedSize(width, height)

        # Execute the message box and return the clicked button text
        clicked_button = msg_box.exec_()
        clicked_button_text = buttons[clicked_button]
        return clicked_button_text

    @staticmethod
    def copy_to_clipboard(text: str):
        pyperclip.copy(text)

    @staticmethod
    def edit_login_data(entries: list, original_button, button_data: dict):
        current_provider = LockerMem.current_search_set["name"]

        if current_provider == entries[0].get():
            LockerMem.locker_set[current_provider] = [entries[1].get(), entries[2].get()]
        else:
            LockerMem.locker_set[entries[0].get()] = [entries[1].get(), entries[2].get()]
            del LockerMem.locker_set[current_provider]

        # exit edit mode
        for entry in entries:
            entry.configure(state="readonly")

        # update memory (exited out of edit mode) # set cache var back
        GUIMem.cache[2] = False

        # Store (modified) locker to file
        # 1. encode locker  (+ convert to json type dict)
        enc_locker = cryptography_protector.encrypt(data=json.dumps(LockerMem.locker_set, indent=2),
                                                    key=LockerMem.user_seed)
        # 2. store to file
        FileSystem.save_locker_file(encoded_content=enc_locker)
        messagebox.showinfo(title=appName, message="Changes were successfully saved!")

        # 3. restore original button
        original_button.configure(**button_data)

    @staticmethod
    def import_logins(file_path: str):
        with open(file_path, "r", encoding="utf-8") as import_file:
            # Merge lockers (with user handle in exception)
            merged = Features.merge_lockers(locker_dict1=LockerMem.locker_set, locker_dict2=json.load(import_file))

            # Update LockerMem
            LockerMem.locker_set = merged

            # Store (modified) locker to file
            # 1. encode locker  (+ convert to json type dict)
            enc_locker = cryptography_protector.encrypt(data=json.dumps(LockerMem.locker_set, indent=2),
                                                        key=LockerMem.user_seed)
            # 2. store to file
            FileSystem.save_locker_file(encoded_content=enc_locker)

            messagebox.showinfo(title=appName, message="Login data was imported successfully!")


class Fonts:
    __default_font_only = "Roboto"
    headline = (__default_font_only, 25, "bold")
    large = (__default_font_only, 15)
    bold = (__default_font_only, 15, "bold")
    bold_large = (__default_font_only, 20, "bold")
    default = (__default_font_only, 12)


class GUI:
    @staticmethod
    def create_root_window():
        root_obj = cutk.CTk()
        root_obj.title(appName)
        root_obj.geometry("460x250")
        root_obj.resizable(False, False)
        cutk.set_default_color_theme("green")

        # Title
        title_frame = cutk.CTkFrame(master=root_obj)
        icon = cutk.CTkImage(dark_image=Image.open(icon_path), size=(50, 50))
        icon_label = cutk.CTkLabel(master=title_frame, image=icon, text="")
        icon_label.pack(side="left", padx=(10, 5))
        title_label = cutk.CTkLabel(master=title_frame, text=appName, font=Fonts.headline)
        title_label.pack(padx=(5, 10))
        sub_title = cutk.CTkLabel(master=title_frame, text="By Benjy", font=Fonts.bold)
        sub_title.pack()
        title_frame.pack(pady=8)

        # add root to GUIMem
        GUIMem.root_obj = root_obj
        # run login sequence
        match LockerMem.new_user:
            case True:
                GUI.new_password_sequence()
            case False:
                GUI.login_sequence()
                pass

        root_obj.mainloop()

    @staticmethod
    def new_password_sequence():
        # info label
        info_label = cutk.CTkLabel(master=GUIMem.root_obj, text="Create your Login Locker password")
        info_label.pack(pady=(15, 0))

        if LockerMem.new_user is False:
            abort_button = cutk.CTkButton(master=GUIMem.root_obj, text="abort", width=20, height=15,
                                          command=GUILogic.switch_to_main_sequence)
            abort_button.pack()

            old_p_frame = cutk.CTkFrame(master=GUIMem.root_obj)
            old_pass_entry = cutk.CTkEntry(master=old_p_frame, placeholder_text="Current password", width=250,
                                           show="*")
            old_pass_entry.pack(side="left", padx=5)

            # show password button
            show_old_password_button = cutk.CTkButton(master=old_p_frame, text="Show", width=50,
                                                      command=lambda: GUILogic.show_password(
                                                          entry_object=old_pass_entry,
                                                          button_object=show_old_password_button,
                                                          cache_index=0)
                                                      )
            show_old_password_button.pack(padx=5)

            old_p_frame.pack(pady=(10, 10))

            GUIMem.add_widgets([abort_button, old_p_frame])

        # password entry
        p_frame = cutk.CTkFrame(master=GUIMem.root_obj)
        password_entry1 = cutk.CTkEntry(master=p_frame, placeholder_text="Your password", width=250, show="*")
        password_entry1.pack(side="left", padx=5)

        # show password button
        show_password_button = cutk.CTkButton(master=p_frame, text="Show", width=50,
                                              command=lambda: GUILogic.show_password(entry_object=password_entry1,
                                                                                     button_object=show_password_button,
                                                                                     cache_index=1)
                                              )
        show_password_button.pack(padx=5)

        p_frame.pack(pady=(10, 5))

        # password entry 2
        p_frame2 = cutk.CTkFrame(master=GUIMem.root_obj)
        password_entry2 = cutk.CTkEntry(master=p_frame2, placeholder_text="Repeat new password", width=250, show="*")
        password_entry2.pack(padx=5, side="left")

        # show password button
        show_password_button2 = cutk.CTkButton(master=p_frame2, text="Show", width=50,
                                               command=lambda:
                                               GUILogic.show_password(entry_object=password_entry2,
                                                                      button_object=show_password_button2,
                                                                      cache_index=2)
                                               )
        show_password_button2.pack(padx=5)

        p_frame2.pack(pady=(5, 10))

        # save password
        log_in_button = cutk.CTkButton(master=GUIMem.root_obj, text="Save",
                                       command=lambda: GUILogic.new_password_helper(password_entry1, password_entry2))
        log_in_button.pack(pady=5)
        if LockerMem.new_user is False:
            log_in_button.configure(command=lambda: GUILogic.new_password_helper(password_entry1, password_entry2,
                                                                                 old_pass_entry))

        # bind root to login_button for comfort
        GUIMem.current_bind = lambda: GUILogic.new_password_helper(password_entry1, password_entry2)
        GUIMem.root_obj.unbind("<Return>")
        GUIMem.root_obj.bind("<Return>", func=GUILogic.bind_helper)

        # add every widget to widget memory
        GUIMem.add_widgets([info_label, p_frame, p_frame2, log_in_button])

    @staticmethod
    def login_sequence():
        GUIMem.root_obj.geometry("460x250")

        # info label
        info_label = cutk.CTkLabel(master=GUIMem.root_obj, text="Enter your Login Locker password")
        info_label.pack(pady=(15, 0))

        # password entry
        p_frame = cutk.CTkFrame(master=GUIMem.root_obj)
        password_entry = cutk.CTkEntry(master=p_frame, placeholder_text="Your password", width=250, show="*")
        password_entry.pack(side="left", padx=5)

        # show password button
        show_password_button = cutk.CTkButton(master=p_frame, text="Show", width=50,
                                              command=lambda: GUILogic.show_password(entry_object=password_entry,
                                                                                     button_object=show_password_button)
                                              )
        show_password_button.pack(padx=5)
        p_frame.pack()

        # log in button
        log_in_button = cutk.CTkButton(master=GUIMem.root_obj, text="Login",
                                       command=lambda: GUILogic.verify_login(password_entry))
        log_in_button.pack(pady=(20, 0))

        # bind root to login_button for comfort
        GUIMem.current_bind = lambda: GUILogic.verify_login(password_entry)
        GUIMem.root_obj.unbind("<Return>")
        GUIMem.root_obj.bind("<Return>", func=GUILogic.bind_helper)

        # add every widget to widget memory
        GUIMem.add_widgets([info_label, p_frame, log_in_button])

        # set the default button color
        GUIMem.button_color = log_in_button._fg_color  # noqa

    @staticmethod
    def main_sequence():
        # main_frame
        main_frame = cutk.CTkFrame(master=GUIMem.root_obj)

        info_label = cutk.CTkLabel(master=main_frame, text="Save your login data", font=Fonts.bold_large)
        info_label.pack()

        account_label = cutk.CTkLabel(master=main_frame, text="Account Provider", font=Fonts.bold)
        account_label.pack(pady=(15, 0))
        account_entry = cutk.CTkEntry(master=main_frame, width=210, placeholder_text='for e.g.: "Google"')
        account_entry.pack()

        email_label = cutk.CTkLabel(master=main_frame, text="Email / Username / Number", font=Fonts.bold)
        email_label.pack(pady=(15, 0), padx=10)
        email_entry = cutk.CTkEntry(master=main_frame, width=210, placeholder_text='for e.g.: "someone@example.com"')
        email_entry.pack()

        password_label = cutk.CTkLabel(master=main_frame, text="Password", font=Fonts.bold)
        password_label.pack(pady=(15, 0))
        password_entry = cutk.CTkEntry(master=main_frame, width=210, placeholder_text='New Password', show="*")
        password_entry.pack()

        sub_frame = cutk.CTkFrame(master=main_frame)

        gen_pass_button = cutk.CTkButton(master=sub_frame, text="Generate", width=70,
                                         command=lambda: GUILogic.handle_pass_gen(entry_object=password_entry))
        gen_pass_button.pack(side="left", padx=5)

        show_password_button = cutk.CTkButton(master=sub_frame, text="Show", width=70,
                                              command=lambda: GUILogic.show_password(entry_object=password_entry,
                                                                                     button_object=show_password_button)
                                              )
        show_password_button.pack(padx=5)

        sub_frame.pack(pady=(5, 10))

        save_button = cutk.CTkButton(master=main_frame, text="Save Login Data", width=180,
                                     command=lambda: GUILogic.save_login_button(
                                         {account_entry.get(): [email_entry.get(), password_entry.get()]})
                                     )
        save_button.pack(pady=(15, 10))

        misc_frame = cutk.CTkFrame(master=main_frame)

        all_logins_button = cutk.CTkButton(master=misc_frame, text="My Logins", width=100,
                                         command=GUILogic.switch_to_all_logins_sequence)
        all_logins_button.pack(side="left", padx=5)

        settings_button = cutk.CTkButton(master=misc_frame, text="Settings", width=100,
                                         command=GUILogic.switch_to_settings_sequence)
        settings_button.pack(side="left", padx=5)
        misc_frame.pack(pady=(0, 5))


        main_frame.pack(pady=15)

        # bind new functions
        GUIMem.current_bind = lambda: GUILogic.save_login_button(
            {account_entry.get(): [email_entry.get(), password_entry.get()]}
        )
        GUIMem.cache_bind = GUIMem.current_bind
        GUIMem.root_obj.unbind("<Return>")
        GUIMem.root_obj.bind("<Return>", func=GUILogic.bind_helper)

        # add widgets to memory
        GUIMem.add_widgets([main_frame])

        # Set main_frame as current main_obj
        GUIMem.main_widget = main_frame



    @staticmethod
    def settings_sequence():
        settings_frame = cutk.CTkFrame(master=GUIMem.root_obj)

        close_button = cutk.CTkButton(master=settings_frame, text="Close", width=20, height=15,
                                      command=GUILogic.return_to_main_sequence)
        close_button.pack(pady=5)

        change_password_button = cutk.CTkButton(master=settings_frame, text="Change Locker password", width=175,
                                                command=GUILogic.switch_to_new_password_sequence)
        change_password_button.pack()

        export_button = cutk.CTkButton(master=settings_frame, text="Export all logins", width=175,
                                       command=lambda: Features.export_as_file(locker_dict=LockerMem.locker_set))
        export_button.pack(pady=(5, 5))

        import_button = cutk.CTkButton(master=settings_frame, text="Import logins", width=175,
                                       command=GUILogic.handle_import)
        import_button.pack()

        settings_frame.pack(side="right", padx=15)

        # add widgets and frames to subliminal widgets
        GUIMem.add_subs([settings_frame])


    @staticmethod
    def all_logins_sequence():
        all_logins_frame = cutk.CTkFrame(master=GUIMem.root_obj, height=450, width=400)

        close_button = cutk.CTkButton(master=all_logins_frame, text="Close", width=20, height=15,
                                      command=GUILogic.return_to_main_sequence)
        close_button.pack(pady=5)

        left_frame = cutk.CTkFrame(master=all_logins_frame, height=380)

        def search_button_call(entry_value):
            # update entries
            GUILogic.handle_search(account_search=entry_value,
                                   account_provider_obj=provider_entry,
                                   email_obj=email_entry,
                                   password_obj=password_entry)

            # select item in listbox
            if provider_entry.get() != "Not Found":
                idx = list(LockerMem.locker_set.keys()).index(provider_entry.get())
                list_box.activate(index=idx)
                list_box.see(index=idx)
            else:
                list_box.deactivate(0)

        search_label = cutk.CTkLabel(master=left_frame, text="Search For Your Account", font=Fonts.bold)
        search_label.pack()

        bar_frame = cutk.CTkFrame(master=left_frame)
        search_entry = cutk.CTkEntry(master=bar_frame, width=210, placeholder_text='for e.g.: "Google"')
        search_entry.pack(side="left")
        search_button = cutk.CTkButton(master=bar_frame, text="Search", width=10,
                                       command=lambda: search_button_call(search_entry.get()))
        search_button.pack()
        bar_frame.pack(padx=5)


        copy_icon_obj = cutk.CTkImage(dark_image=Image.open(copy_icon), size=(15, 15))

        provider_frame = cutk.CTkFrame(master=left_frame)
        provider_label = cutk.CTkLabel(master=provider_frame, text=f"Account Provider:")
        provider_label.grid(column=0, row=0, padx=5)
        provider_entry = cutk.CTkEntry(master=provider_frame, width=200)
        provider_entry.grid(column=0, row=1)
        provider_entry.insert(0, "N/A")
        provider_entry.configure(state="readonly")
        provider_copy_button = cutk.CTkButton(master=provider_frame, text="", image=copy_icon_obj, width=15,
                                              command=lambda: GUILogic.copy_button(provider_entry.get(),
                                                                                   provider_copy_button))
        provider_copy_button.grid(column=1, row=1, padx=5)
        provider_frame.pack(pady=(10, 0))

        email_frame = cutk.CTkFrame(master=left_frame)
        email_label = cutk.CTkLabel(master=email_frame, text=f"Email:")
        email_label.grid(column=0, row=0, padx=5)
        email_entry = cutk.CTkEntry(master=email_frame, width=200)
        email_entry.grid(column=0, row=1)
        email_entry.insert(0, "N/A")
        email_entry.configure(state="readonly")
        email_copy_button = cutk.CTkButton(master=email_frame, text="", image=copy_icon_obj, width=15,
                                           command=lambda: GUILogic.copy_button(email_entry.get(),
                                                                                email_copy_button))
        email_copy_button.grid(column=1, row=1, padx=5)
        email_frame.pack()

        password_frame = cutk.CTkFrame(master=left_frame)
        password_label = cutk.CTkLabel(master=password_frame, text=f"Password:")
        password_label.grid(column=0, row=0, padx=5)
        password_entry = cutk.CTkEntry(master=password_frame, width=200)
        password_entry.grid(column=0, row=1)
        password_entry.insert(0, "N/A")
        password_entry.configure(state="readonly")
        password_copy_button = cutk.CTkButton(master=password_frame, text="", image=copy_icon_obj, width=15,
                                              command=lambda: GUILogic.copy_button(password_entry.get(),
                                                                                   password_copy_button))
        password_copy_button.grid(column=1, row=1, padx=5)
        password_frame.pack(pady=(0, 5))

        edit_button = cutk.CTkButton(master=left_frame, text="Edit", width=80,
                                     command=lambda: GUILogic.enter_edit_mode(
                                         entries=[provider_entry, email_entry, password_entry],
                                         button_object=delete_button))
        edit_button.pack(pady=(0, 5), side="left", padx=(50, 0))

        delete_button = cutk.CTkButton(master=left_frame, text="Delete", width=80,
                                       command=lambda: GUILogic.delete_login_button(
                                           account_provider=provider_entry.get()))
        delete_button.pack(padx=(0, 50))

        left_frame.pack(side="left")

        def update_info(selected_item):
            GUILogic.handle_search(account_search=selected_item,
                                   account_provider_obj=provider_entry,
                                   email_obj=email_entry,
                                   password_obj=password_entry)


        list_box = CTkListbox.CTkListbox(master=all_logins_frame, command=update_info, height=400, width=200)

        list_box.pack(side="right", fill="both", expand=True, padx=20, pady=10)


        ThreadHandler.ThreadHandler.run_daemon(lambda: GUILogic.fill_all_logins_box(list_box))
        all_logins_frame.pack(side="right", padx=15)

        # add widgets and frames to subliminal widgets
        GUIMem.add_subs([all_logins_frame])

        # rebind button
        GUIMem.current_bind = lambda: search_button_call(search_entry.get())
        GUIMem.root_obj.bind("<Return>", func=GUILogic.bind_helper)



class GUILogic:
    @staticmethod
    def change_resolution(new_resolution: str):
        GUIMem.root_obj.geometry(new_resolution)

    @staticmethod
    def set_appearance(mode: str):
        mode = mode.lower()
        available_modes = ["light", "dark", "system"]
        if mode in available_modes:
            cutk.set_appearance_mode(mode)
        else:
            raise ValueError(f"{mode} not in {available_modes}!")

    @staticmethod
    def copy_button(text, button_obj):
        def color_animation(default, new):
            button_obj.configure(fg_color=new, hover_color=new)
            time.sleep(0.2)
            button_obj.configure(fg_color=default, hover_color=default)

        if text and text not in ["N/A", "Not Found"]:
            pyperclip.copy(text)
            ThreadHandler.ThreadHandler.run_daemon(lambda: color_animation(GUIMem.button_color, "#8FD1FF"))
        else:
            ThreadHandler.ThreadHandler.run_daemon(lambda: color_animation(GUIMem.button_color, "red"))

    @staticmethod
    def show_password(entry_object, button_object, **kwargs):
        # cache_index should be passed as a keyword argument
        cache_index = kwargs.get('cache_index')
        match cache_index:
            case None:
                # use normal show_password variable
                if GUIMem.show_password is True:
                    GUIMem.show_password = False
                    entry_object.configure(show="*")
                    button_object.configure(text="Show")
                else:
                    GUIMem.show_password = True
                    entry_object.configure(show="")
                    button_object.configure(text="Hide")
            case _:
                cache_index = int(cache_index)
                if GUIMem.cache[cache_index] is True:  # the cache is expected to be a len() of 3
                    GUIMem.cache[cache_index] = False
                    entry_object.configure(show="*")
                    button_object.configure(text="Show")
                else:
                    GUIMem.cache[cache_index] = True
                    entry_object.configure(show="")
                    button_object.configure(text="Hide")

    @staticmethod
    def enter_edit_mode(entries: list, button_object):
        # check if there even is anything to edit
        if entries[0].get() in ["N/A", "Not Found"]:
            messagebox.showerror(title=appName, message="There is nothing to be edited!")
            return

        # check if already in edit mode -> the last cache index is used for that
        if GUIMem.cache[2] is False:
            GUIMem.cache[2] = True
        else:
            return

        # configure entries
        for entry in entries:
            entry.configure(state="normal")

        # hold original button data
        button_data = {"text": button_object.cget("text"),
                       "command": button_object.cget("command")
                       }

        # change button
        button_object.configure(text="Save", command=lambda: Features.edit_login_data(entries=entries,
                                                                                      original_button=button_object,
                                                                                      button_data=button_data))

    @staticmethod
    def handle_import():
        path = filedialog.askopenfilename(title="Select Json File", filetypes=[("JSON files", "*.json")])
        if path is not None:
            Features.import_logins(path)
        return

    @staticmethod
    def switch_to_main_sequence():
        # update current sequence
        GUIMem.current_sequence = GUILogic.switch_to_main_sequence

        # set GUIMem cache to default
        GUIMem.reset_cache()

        # first destroy every current widget
        GUILogic.gui_object_destroyer(GUIMem.widgets)
        GUILogic.gui_object_destroyer(GUIMem.subliminal_widgets)

        # Remove destroyed widgets from memory
        GUIMem.clear_widgets()
        GUIMem.clear_subs()

        # unbind login_button from root and remove from memory
        GUIMem.root_obj.unbind("<Return>")
        GUIMem.current_bind = None
        GUIMem.show_password = False

        # initialise for main sequence
        GUILogic.change_resolution(new_resolution="460x480")  # noqa  // change res

        # now run main sequence
        GUI.main_sequence()

    @staticmethod
    def return_to_main_sequence():
        # update current sequence
        GUIMem.current_sequence = GUILogic.return_to_main_sequence

        # set GUIMem cache to default
        GUIMem.reset_cache()

        # destroy subs
        GUILogic.gui_object_destroyer(GUIMem.subliminal_widgets)
        GUIMem.clear_subs()

        # unbind login_button from root and remove from memory
        GUIMem.root_obj.unbind("<Return>")
        GUIMem.root_obj.bind("<Return>", func=GUILogic.bind_helper)
        GUIMem.current_bind = GUIMem.cache_bind

        # initialise for main sequence
        GUILogic.change_resolution(new_resolution="460x480")  # noqa  // change res

        # change main_frame package to side="left"
        GUIMem.main_widget.pack(side="top")

    @staticmethod
    def switch_to_new_password_sequence():
        # update current sequence
        GUIMem.current_sequence = GUILogic.switch_to_new_password_sequence

        # set GUIMem cache to default
        GUIMem.reset_cache()

        # destroy widgets
        GUILogic.gui_object_destroyer(GUIMem.subliminal_widgets)
        GUILogic.gui_object_destroyer(GUIMem.widgets)

        # remove from memory
        GUIMem.clear_widgets()
        GUIMem.clear_subs()

        # change res
        match LockerMem.new_user:
            case False:
                GUIMem.root_obj.geometry("460x350")
            case True:
                GUIMem.root_obj.geometry("460x250")

        # run sequence
        GUI.new_password_sequence()


    @staticmethod
    def switch_to_all_logins_sequence():
        # update current sequence
        GUIMem.current_sequence = GUILogic.switch_to_all_logins_sequence

        # set GUIMem cache to default
        GUIMem.reset_cache()

        # destroy every current subliminal widget
        GUILogic.gui_object_destroyer(GUIMem.subliminal_widgets)

        # Remove destroyed subliminal widgets from memory
        GUIMem.clear_subs()

        # change resolution
        GUILogic.change_resolution(new_resolution="850x550")  # noqa  // change res

        # change main_frame package to side="left"
        GUIMem.main_widget.pack(side="left", padx=15)

        # now run search sequence
        GUI.all_logins_sequence()

    @staticmethod
    def switch_to_settings_sequence():
        # update current sequence
        GUIMem.current_sequence = GUILogic.switch_to_settings_sequence

        # set GUIMem cache to default
        GUIMem.reset_cache()

        # destroy every current subliminal widget
        GUILogic.gui_object_destroyer(GUIMem.subliminal_widgets)

        # Remove destroyed subliminal widgets from memory
        GUIMem.clear_subs()

        # change resolution
        GUILogic.change_resolution(new_resolution="470x480")  # noqa  // change res

        # change main_frame package to side="left"
        GUIMem.main_widget.pack(side="left", padx=15)

        # now run search sequence
        GUI.settings_sequence()

    @staticmethod
    def handle_search(account_search: str, account_provider_obj, email_obj, password_obj):
        # check if currently in edit mode
        if GUIMem.cache[2] is True:
            messagebox.showerror(title=appName, message="You are currently editing some data, please save your changes"
                                                        " first.")
            return

        if account_search in ["", "  "]:
            return

        def update_entry(entry_object, text: str):
            entry_object.configure(state="normal")
            entry_object.delete(0, cutk.END)
            entry_object.insert(0, text)
            entry_object.configure(state="readonly")

        # search for given account provider
        search_set = Features.search_login(locker_dict=LockerMem.locker_set, key=account_search)

        # store to memory
        LockerMem.current_search_set = search_set

        # update GUI
        update_entry(account_provider_obj, search_set["name"])
        update_entry(email_obj, search_set["email"])
        update_entry(password_obj, search_set["password"])

    @staticmethod
    def gui_object_destroyer(gui_objects: list):
        for obj in gui_objects:
            obj.destroy()

    @staticmethod
    def fill_all_logins_box(list_box_obj):
        all_accounts = LockerMem.locker_set.keys()

        for idx, key in enumerate(all_accounts):
            list_box_obj.insert(idx, key)


    @staticmethod
    def verify_login(entry_object):
        # generate seed and try to decode locker
        seed_from_pass = cryptography_protector.generate_key(seed=entry_object.get(), salt=FileSystem.load_salt())

        # load locker (with decryption and everything)
        try:
            tmp_locker = DictionaryHandler.get_locker(seed=seed_from_pass)
            # since it worked, write locker and seed to memory
            LockerMem.locker_set = tmp_locker
            LockerMem.user_seed = seed_from_pass

            # now switch to main sequence
            GUILogic.switch_to_main_sequence()

        except InvalidToken:
            # show error message
            messagebox.showerror(title=appName, message="Password is incorrect!")

            # clear entry
            entry_object.delete(0, cutk.END)

    @staticmethod
    def bind_helper(*args):  # noqa
        GUIMem.current_bind()

    @staticmethod
    def save_login_button(login_data: dict):
        # check if login_data dict has every information
        key = list(login_data.keys())[0]
        if key == "":
            messagebox.showerror(title=appName, message="You have not set an account provider!")
            return  # end function with this return statement

        elif login_data[key][0] == "" or login_data[key][1] == "":
            messagebox.showerror(title=appName, message="You left the email and/or password as empty!"
                                                        "\nBoth of them are required.")
            return  # end function with this return statement

        # Merge lockers (with user handle in exception)
        merged = Features.merge_lockers(locker_dict1=LockerMem.locker_set, locker_dict2=login_data)

        # Update LockerMem
        LockerMem.locker_set = merged

        # Store (modified) locker to file
        # 1. encode locker  (+ convert to json type dict)
        enc_locker = cryptography_protector.encrypt(data=json.dumps(LockerMem.locker_set, indent=2),
                                                    key=LockerMem.user_seed)
        # 2. store to file
        FileSystem.save_locker_file(encoded_content=enc_locker)

        messagebox.showinfo(title=appName, message="Login data stored successfully!")

        # Switch to current sequence
        GUIMem.current_sequence()

    @staticmethod
    def handle_pass_gen(entry_object):
        # clear entry
        entry_object.delete(0, cutk.END)

        # put in new pass
        entry_object.insert(0, Features.generate_password(length=16))

    @staticmethod
    def new_password_helper(password_entry1, password_entry2, *old_password):
        # if old pass is present (in case of a password change) check if it's correct
        if old_password and not cryptography_protector.generate_key(seed=old_password[0].get(),
                                                                    salt=FileSystem.load_salt()) == LockerMem.user_seed:
            messagebox.showerror(title=appName, message="Not the correct current password!")
            return

        # check if passwords are blank
        if password_entry1.get() == "" or password_entry2.get() == "":
            messagebox.showerror(title=appName, message="You can't leave your password blank!")
            return

        # check if passwords are matching
        elif not password_entry1.get() == password_entry2.get():
            messagebox.showerror(title=appName, message="The passwords are not matching!")
            password_entry2.delete(0, cutk.END)
            return

        # if passwords are matching and not blank
        else:
            # Check for at least one capital letter
            has_capital = re.search(r'[A-Z]', password_entry1.get()) is not None
            # Check for at least one small letter
            has_small = re.search(r'[a-z]', password_entry1.get()) is not None
            # Check for at least one number
            has_number = re.search(r'\d', password_entry1.get()) is not None
            # Check for at least one punctuation
            has_punctuation = re.search(r'[!"#$%&\'()*+,-.[/:;<=>?@\\^_`{|}~]', password_entry1.get()) is not None
            if "]" in password_entry1.get():  # this is a workaround because you can't have "]" in the r'' string
                has_punctuation = True

            # check if all requirements are met
            requirements = {"capital letter": has_capital,
                            "small letter": has_small,
                            "number": has_number,
                            "punctuation": has_punctuation}

            if not all(requirements.values()):
                # all not met requirements
                not_met_requirements = [req for req in list(requirements.keys()) if not requirements[req]]
                err_msg = f"Your password is missing "

                nmr_count = len(not_met_requirements)
                for idx, nmr in enumerate(not_met_requirements):
                    # check if it's the last nmr to mention and more than one nmr is to be mentioned
                    if 1 < nmr_count == idx + 1:
                        err_msg += "and "

                    # add the nmr
                    err_msg += f"a {nmr}"

                    # add a comma if there is more to mention
                    if 1 < nmr_count > idx + 1:
                        err_msg += ", "

                # add the full stop
                err_msg += "."

                messagebox.showerror(title=appName, message=err_msg)
                return

            # generate seed and salt and update locker memory
            salt = cryptography_protector.generate_salt()
            FileSystem.save_salt(generated_salt=salt)
            LockerMem.user_seed = cryptography_protector.generate_key(seed=password_entry1.get(),
                                                                      salt=salt)

            # create a file and encode it
            FileSystem.create_locker_file()

            FileSystem.save_locker_file(
                encoded_content=cryptography_protector.encrypt(data=json.dumps(LockerMem.locker_set, indent=2),
                                                               key=LockerMem.user_seed)
            )

            # give done message
            messagebox.showinfo(title=appName, message="New password was stored successfully!")

            # Destroy all widgets
            GUILogic.gui_object_destroyer(GUIMem.widgets)
            GUILogic.gui_object_destroyer(GUIMem.subliminal_widgets)
            GUIMem.clear_widgets()
            GUIMem.clear_subs()

            # Switch to main sequence
            GUILogic.switch_to_main_sequence()

    @staticmethod
    def delete_login_button(account_provider: str):
        if account_provider not in ["N/A", "Not Found"]:
            if messagebox.askyesno(title=appName,
                                   message=f"Are you sure you want to delete {account_provider} login data?"):
                Features.remove_from_locker(account_provider)
                GUIMem.current_sequence()

class GUIWidgetMemory:
    def __init__(self):
        self.root_obj = None  # this is the window object
        self.current_bind = None  # this is set to the function the "Return" key performs
        self.cache_bind = None  # store a bind in between

        self.show_password = False  # if false, doesn't show password, else it does
        self.cache = [False, False, False]  # can be used where ever wanted

        # # widgets
        self.widgets = []  # list of every (main/important) widget

        # list of misc widgets that are sorted out from main, so they can be destroyed
        # without modifying or searching for them in the widgets list
        self.subliminal_widgets = []

        # this is set to the widget or frame in order for it to be modified by other sequences
        self.main_widget = None

        # current sequence
        self.current_sequence = None

        # colors
        self.button_color = None


    def clear_widgets(self):
        self.widgets = []

    def add_widgets(self, new_widgets: list):
        for widget in new_widgets:
            self.widgets.append(widget)

    def remove_widgets(self, widgets_to_remove: list):
        for widget in widgets_to_remove:
            self.widgets.remove(widget)

    def unbind_gui(self):
        self.current_bind = None

    # subs
    def clear_subs(self):
        self.subliminal_widgets = []

    def add_subs(self, new_widgets: list):
        for widget in new_widgets:
            self.subliminal_widgets.append(widget)

    def remove_subs(self, widgets_to_remove: list):
        for widget in widgets_to_remove:
            self.widgets.remove(widget)

    def reset_cache(self):
        self.cache = [False, False, False]


class LockerMemory:
    def __init__(self):
        self.user_seed = b""
        self.locker_set = {}
        self.current_search_set = {}
        self.default_email = ""
        self.new_user = False


if __name__ == '__main__':
    # app info
    appName = "Login Locker V3"

    # paths
    bin_path = os.path.join("./", "bin")
    locker_file = os.path.join(bin_path, "logins.ll3")
    last_email_file = os.path.join(bin_path, "email.ll3")
    salt_file = os.path.join(bin_path, "salt.ll3")
    icon_path = os.path.join(bin_path, "images", "login.png")
    copy_icon = os.path.join(bin_path, "images", "copy.png")

    # LockerMem + initialise file system
    LockerMem = LockerMemory()
    FileSystem.initialisation()

    # GUI
    GUIMem = GUIWidgetMemory()
    GUI.create_root_window()  # run gui
