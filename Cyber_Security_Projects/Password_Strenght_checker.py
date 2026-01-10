import re
print("Script is running...")
password = input("Enter the password : ")

if len(password)<8:
    print("Password must be atleast 8 characters long.")

elif not re.search("[A-Z]",password):
    print("Password must contain atleast one uppercase letter.")

elif not re.search("[a-z]",password):
    print("Password must contain atleast one lowercase letter.")

elif not re.search("[0-9]",password):
    print("Password must contain atleast one digit.")

else:
    print("Password is strong.")
