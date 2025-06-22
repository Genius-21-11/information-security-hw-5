import re
import hashlib

def check_password_complexity(password):
    # Проверка длины
    if len(password) < 8:
        print("Пароль должен содержать не менее 8 символов.")
        return False

    # Проверка наличия прописных букв
    if not re.search(r"[A-Z]", password):
        print("Пароль должен содержать хотя бы одну прописную букву.")
        return False

    # Проверка наличия строчных букв
    if not re.search(r"[a-z]", password):
        print("Пароль должен содержать хотя бы одну строчную букву.")
        return False

    # Проверка наличия цифр
    if not re.search(r"\d", password):
        print("Пароль должен содержать хотя бы одну цифру.")
        return False

    return True

def main():
    password = input("Введите пароль: ")

    if check_password_complexity(password):
        # Переводим пароль в хэш-значение (SHA-256)
        hash_object = hashlib.sha256(password.encode())
        hash_hex = hash_object.hexdigest()
        print(f"Хэш пароля: {hash_hex}")
    else:
        print("Пароль не соответствует требованиям сложности.")

if __name__ == "__main__":
    main()