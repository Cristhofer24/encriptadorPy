import os
import rsa
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk  # Importa Pillow para cargar imágenes en otros formatos
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Contraseña de acceso
ACCESS_PASSWORD = "123"

# Función para generar clave y cifrar datos simétricamente
def encrypt_symmetric(key, data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

# Función para descifrar datos simétricos
def decrypt_symmetric(key, encrypted_data):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data[16:]) + decryptor.finalize()

# Genera claves RSA pública y privada
def generate_rsa_keys():
    public_key, private_key = rsa.newkeys(2048)
    return public_key, private_key

# Verifica contraseña
def check_password():
    password = simpledialog.askstring("Contraseña", "Introduce la contraseña para continuar:", show="*")
    return password == ACCESS_PASSWORD

# Función para cifrar el archivo seleccionado
def encrypt_file():
    if not check_password():
        messagebox.showerror("Error", "Contraseña incorrecta.")
        return
    
    file_path = filedialog.askopenfilename(title="Selecciona un archivo para cifrar")
    if not file_path:
        return
    
    try:
        aes_key = os.urandom(32)
        public_key, private_key = generate_rsa_keys()
        
        with open(file_path, "rb") as file:
            data = file.read()
        encrypted_data = encrypt_symmetric(aes_key, data)
        encrypted_key = rsa.encrypt(aes_key, public_key)

        output_file = file_path + ".enc"
        with open(output_file, "wb") as file:
            file.write(encrypted_key + encrypted_data)

        messagebox.showinfo("Éxito", f"Archivo cifrado guardado como: {output_file}")

    except Exception as e:
        messagebox.showerror("Error", f"Error al cifrar el archivo: {e}")

# Función para cifrar texto ingresado por el usuario con RSA
def encrypt_input_text():
    if not check_password():
        messagebox.showerror("Error", "Contraseña incorrecta.")
        return

    text = simpledialog.askstring("Entrada de texto", "Escribe el texto a cifrar:")
    if not text:
        return

    try:
        public_key, private_key = generate_rsa_keys()
        encrypted_text = rsa.encrypt(text.encode('utf-8'), public_key)

        with open("public_key.pem", "wb") as pub_key_file:
            pub_key_file.write(public_key.save_pkcs1("PEM"))
        with open("encrypted_text.bin", "wb") as enc_text_file:
            enc_text_file.write(encrypted_text)

        messagebox.showinfo("Éxito", "Texto cifrado y clave pública guardados exitosamente.")

    except Exception as e:
        messagebox.showerror("Error", f"Error al cifrar el texto: {e}")

# Función para descifrar el archivo seleccionado
def decrypt_file():
    if not check_password():
        messagebox.showerror("Error", "Contraseña incorrecta.")
        return
    
    file_path = filedialog.askopenfilename(title="Selecciona un archivo para descifrar", filetypes=[("Encrypted files", "*.enc")])
    if not file_path:
        return
    
    try:
        with open(file_path, "rb") as file:
            encrypted_key = file.read(256)
            encrypted_data = file.read()

        aes_key = rsa.decrypt(encrypted_key, private_key)
        decrypted_data = decrypt_symmetric(aes_key, encrypted_data)

        output_file = file_path.replace(".enc", "_decrypted")
        with open(output_file, "wb") as file:
            file.write(decrypted_data)

        messagebox.showinfo("Éxito", f"Archivo descifrado guardado como: {output_file}")

    except Exception as e:
        messagebox.showerror("Error", f"Error al descifrar el archivo: {e}")

# Configura la interfaz gráfica con tkinter
root = tk.Tk()
root.title("Cifrador de Archivos y Texto")
root.geometry("500x500")
root.configure(bg="#282c34")

# Cargar la imagen y mostrarla en la interfaz principal
img_path = "D:\\Escritorio\\taller1\\img\\candado.png"
img = Image.open(img_path)
img = img.resize((200, 200), Image.LANCZOS)  # Ajusta el tamaño de la imagen
photo = ImageTk.PhotoImage(img)

img_label = tk.Label(root, image=photo, bg="#282c34")
img_label.pack(pady=10)

title_label = tk.Label(root, text="Cifrador de Archivos y Texto", font=("Arial", 18, "bold"), bg="#282c34", fg="#61dafb")
title_label.pack(pady=10)

# Botón para cifrar archivo
encrypt_file_button = tk.Button(
    root, text="Seleccionar archivo para cifrar", font=("Arial", 12),
    command=encrypt_file, bg="#61dafb", fg="#282c34", width=25, height=2
)
encrypt_file_button.pack(pady=10)

# Botón para cifrar texto
encrypt_text_button = tk.Button(
    root, text="Ingresar texto para cifrar", font=("Arial", 12),
    command=encrypt_input_text, bg="#61dafb", fg="#282c34", width=25, height=2
)
encrypt_text_button.pack(pady=10)

# Botón para desencriptar archivo
decrypt_file_button = tk.Button(
    root, text="Seleccionar archivo para descifrar", font=("Arial", 12),
    command=decrypt_file, bg="#61dafb", fg="#282c34", width=25, height=2
)
decrypt_file_button.pack(pady=10)

root.mainloop()
