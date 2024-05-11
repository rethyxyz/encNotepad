import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox, font
from cryptography.fernet import Fernet, InvalidToken
import base64
import os
import hashlib
import rethyxyz.rethyxyz
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PROGRAM_TITLE = "encNotepad"

def generate_key(password: str):
    password_bytes = password.encode('utf-8')
    salt = b'\xa3\xb8\xce\xd1\x7f\x3e\x9e\x1c\x8e\xd2\xcb\xac\x2d\x8c\x5f\xbc'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

def encrypt_text(text: str, password: str):
    key = generate_key(password)
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(text.encode('utf-8'))
    return encrypted_text

def decrypt_text(encrypted_text: bytes, password: str):
    try:
        key = generate_key(password)
        cipher = Fernet(key)
        decrypted_text = cipher.decrypt(encrypted_text).decode('utf-8')
        return decrypted_text
    except InvalidToken:
        messagebox.showerror("Error", "Invalid password or corrupted file.")
        return None

def save_file(content: str, password: str, filename=None):
    if not filename:
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not filename:
            return
    encrypted_content = encrypt_text(content, password)
    with open(filename, 'wb') as file:
        file.write(encrypted_content)
    update_title(filename)
    messagebox.showinfo("Success", "Your note was saved successfully.")
    return filename

def update_status_bar(filename="", content=""):
    if filename:
        base_filename = os.path.basename(filename)
    else:
        base_filename = "New File"
    words = len(content.split())
    characters = len(content)
    status_bar.config(text=f"{base_filename} - Words: {words}, Characters: {characters}")

def open_file(password: str):
    filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if not filename:
        return None, None
    with open(filename, 'rb') as file:
        encrypted_content = file.read()
    content = decrypt_text(encrypted_content, password)
    if content is not None:
        text_area.delete("1.0", "end")
        text_area.insert("1.0", content)
        update_title(filename)
        return filename, password
    return None, None

def update_title(filename):
    if filename:
        root.title(f"{os.path.basename(filename)} - {PROGRAM_TITLE}")
    else:
        root.title(f"New File - {PROGRAM_TITLE}")

def get_password(reuse_password=True):
    if reuse_password and hasattr(root, 'password') and root.password:
        use_old = messagebox.askyesno("Password", "Do you want to use the last used password?")
        if use_old:
            return root.password
    return simpledialog.askstring("Password", "Enter a password for encryption:", show='*')

def new_note():
    password = get_password(False)
    if password:
        filename = save_file(text_area.get("1.0", "end-1c"), password)
        if filename:
            root.filename = filename
            root.password = password

def open_note():
    password = get_password()
    if password:
        filename, password = open_file(password)
        if filename:
            root.filename = filename
            root.password = password

def save_current_note():
    if hasattr(root, 'filename') and root.filename and hasattr(root, 'password') and root.password:
        save_file(text_area.get("1.0", "end-1c"), root.password, root.filename)
    else:
        messagebox.showerror("Error", "No file is currently open or password is not set.")

def delete_next_word(event=None):
    cursor_index = text_area.index(tk.INSERT)
    end_of_next_word = text_area.search(r'\s', cursor_index, regexp=True, stopindex=tk.END)
    if end_of_next_word == "":
        end_of_next_word = tk.END
    else:
        end_of_next_word = text_area.index(f"{end_of_next_word} - 1 chars")
    text_area.delete(cursor_index, end_of_next_word)

def delete_previous_word(event=None):
    words = text_area.get("1.0", "end-1c").split(" ")
    if words:
        words.pop()
        text_area.delete("1.0", "end")
        text_area.insert("1.0", " ".join(words))

def adjust_font_size(event):
    current_size = text_font.actual("size")
    if event.delta > 0 or event.num == 4:
        new_size = current_size + 1
    else:
        new_size = current_size - 1 if current_size > 1 else 1
    text_font.configure(size=new_size)

def create_gui():
    global text_area, root, text_font, status_bar
    rethyxyz.rethyxyz.show_intro("encNotepad")
    root = tk.Tk()
    root.title(PROGRAM_TITLE)
    root.geometry("400x400")
    root.filename = None
    root.password = None
    if os.path.isfile('encNotepad.ico'):
        root.iconbitmap('encNotepad.ico')

    text_font = font.Font(family="Lucida Console", size=10)
    background_color = "#333333"
    text_color = "#FFFFFF"
    menu_color = "#555555"
    menu_text_color = "#FFFFFF"

    text_area = tk.Text(root, font=text_font, bg=background_color, fg=text_color, insertbackground=text_color, undo=True)
    text_area.pack(fill=tk.BOTH, expand=True, side=tk.TOP)
    text_area.bind("<Control-s>", lambda event: save_current_note())
    text_area.bind("<Control-BackSpace>", delete_previous_word)
    text_area.bind("<Control-Delete>", delete_next_word)
    text_area.bind("<Control-z>", lambda event: text_area.edit_undo())
    text_area.bind("<Control-y>", lambda event: text_area.edit_redo())
    text_area.bind("<Control-o>", lambda event: open_note())
    text_area.bind("<<Modified>>", lambda event: update_status_bar(root.filename, text_area.get("1.0", "end-1c")))

    root.bind("<Control-MouseWheel>", adjust_font_size)
    root.bind("<Control-Button-4>", adjust_font_size)
    root.bind("<Control-Button-5>", adjust_font_size)

    menu_bar = tk.Menu(root, bg=menu_color, fg=menu_text_color)
    file_menu = tk.Menu(menu_bar, tearoff=0, bg=menu_color, fg=menu_text_color)
    file_menu.add_command(label="New", command=new_note)
    file_menu.add_command(label="Open", command=open_note)
    file_menu.add_command(label="Save", command=save_current_note)
    menu_bar.add_cascade(label="File", menu=file_menu)
    root.config(menu=menu_bar)

    status_bar = tk.Label(root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, bg=menu_color, fg=menu_text_color)
    status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    root.config(bg=background_color)
    root.mainloop()

if __name__ == "__main__":
    create_gui()