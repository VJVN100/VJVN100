def encrpt(text, shift):
    text = text.lower()
    encrypted_text = ''
    for char in text:
        if char.islower():
            encrypted_text += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            encrypted_text += char
    return encrypted_text

msg = input("Enter the message: ")
shift = int(input("Enter the shift value: "))
encryptmsg = encrpt(msg, shift)
print("Encrypted message:", encryptmsg)
