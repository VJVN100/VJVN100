def caesar_shift(message, shift):
    result = ""
    for a in message:
        if a.isalpha():
            char_code = ord(a)
            new_char_code = char_code + shift

            if new_char_code > 90:
                new_char_code = new_char_code - 26
            if new_char_code < 65:
                new_char_code = new_char_code + 26

            new_char = chr(new_char_code)
            result = result + new_char
        else:
            result = result + a

    print(result)

message = input("Enter the message: ").upper()
shift = int(input("Enter the shift value: "))

caesar_shift(message, shift)    
