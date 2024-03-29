import tkinter as tk
from tkinter import messagebox
import random
import string
import pyperclip

class PasswordGenerator:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Generator")

        self.length_label = tk.Label(master, text="Password Length:")
        self.length_label.grid(row=0, column=0, padx=10, pady=10)
        self.length_entry = tk.Entry(master)
        self.length_entry.grid(row=0, column=1, padx=10, pady=10)

        self.lowercase_var = tk.IntVar()
        self.lowercase_check = tk.Checkbutton(master, text="Include Lowercase", variable=self.lowercase_var)
        self.lowercase_check.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W)

        self.uppercase_var = tk.IntVar()
        self.uppercase_check = tk.Checkbutton(master, text="Include Uppercase", variable=self.uppercase_var)
        self.uppercase_check.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W)

        self.digits_var = tk.IntVar()
        self.digits_check = tk.Checkbutton(master, text="Include Digits", variable=self.digits_var)
        self.digits_check.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W)

        self.symbols_var = tk.IntVar()
        self.symbols_check = tk.Checkbutton(master, text="Include Symbols", variable=self.symbols_var)
        self.symbols_check.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W)

        self.generate_button = tk.Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

        self.password_label = tk.Label(master, text="Generated Password:")
        self.password_label.grid(row=6, column=0, padx=10, pady=5, sticky=tk.W)
        self.password_entry = tk.Entry(master, state='readonly')
        self.password_entry.grid(row=6, column=1, padx=10, pady=5, sticky=tk.W+tk.E)

        self.copy_button = tk.Button(master, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

    def generate_password(self):
        length = int(self.length_entry.get())
        if length <= 0:
            messagebox.showerror("Error", "Password length must be greater than 0")
            return

        include_lowercase = bool(self.lowercase_var.get())
        include_uppercase = bool(self.uppercase_var.get())
        include_digits = bool(self.digits_var.get())
        include_symbols = bool(self.symbols_var.get())

        if not (include_lowercase or include_uppercase or include_digits or include_symbols):
            messagebox.showerror("Error", "At least one character type must be selected")
            return

        characters = ''
        if include_lowercase:
            characters += string.ascii_lowercase
        if include_uppercase:
            characters += string.ascii_uppercase
        if include_digits:
            characters += string.digits
        if include_symbols:
            characters += string.punctuation

        generated_password = ''.join(random.choice(characters) for _ in range(length))
        self.password_entry.config(state='normal')
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, generated_password)
        self.password_entry.config(state='readonly')

    def copy_to_clipboard(self):
        password = self.password_entry.get()
        pyperclip.copy(password)
        messagebox.showinfo("Success", "Password copied to clipboard")

def main():
    root = tk.Tk()
    app = PasswordGenerator(root)
    root.mainloop()

if __name__ == "__main__":
    main()
