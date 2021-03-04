from os import getcwd, path, urandom
from win32api import *
from winreg import *
from win32con import *
from win32crypt import *
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def write_exe():
    exe_path = input("\nEnter the path to the folder where the program will be unpacked:\n(Example: D:)"
                     "\nPath: ") + r"\lab#1.exe"
    with open(exe_path, 'wb') as outfile:
        with open(r'D:\lab#1_exe.txt', 'rb') as infile:
            outfile.write(infile.read())
            print("Successfully create lab#1.exe")


def data_collection():
    collected_data = {
        'User name': GetUserName(),
        'Computer name': GetComputerName(),
        'Windows path': GetWindowsDirectory(),
        'System path': GetSystemDirectory(),
        'Mouse buttons': GetSystemMetrics(43),
        'Screen height': GetSystemMetrics(1),
        'Volume memory': GlobalMemoryStatus()['TotalPhys'],
        'Disk serial number': GetVolumeInformation(getcwd()[:3])[1],
    }
    return str(collected_data)


def signing(data):
    key = RSA.generate(2048, urandom)
    hash_data = SHA256.new()
    hash_data.update(data.encode())
    signature = pkcs1_15.new(key).sign(hash_data)
    print("\nHash data successfully recorded")
    with open('D:\\log.pem', 'wb') as file:
        file.write(key.public_key().export_key('PEM'))
    return signature


def write_to_reg(sign):
    key_val = r"SOFTWARE\Stoliarchuk"
    if not path.exists(key_val):
        key = CreateKey(HKEY_CURRENT_USER, key_val)
    registry_key = OpenKey(HKEY_CURRENT_USER, key_val, 0, KEY_SET_VALUE)
    SetValueEx(registry_key, "Signature", 0, REG_BINARY, sign)
    print("\nRegistry key value successfully set")
    CloseKey(registry_key)


def main():
    write_exe()
    data = data_collection()
    print("\nData collected:\n", data)
    sign = signing(data)
    print("Data successfully signed")
    write_to_reg(sign)


if __name__ == '__main__':
    main()
    input()
