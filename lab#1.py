from os import getcwd, path
from win32api import *
from winreg import *
from win32con import *
from win32crypt import *
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


class Guest:
    def __init__(self, charter, name):
        self.charter = charter
        self.name = name
        self.menu()

    def menu(self):
        print('\nYou have a "Guest level"!')
        print('Enter "help" to get information about available commands for each level.')

        while True:
            command = input(f"┌──({self.name}@guest) - [~|help|about|exit|login|~]\n└─$ ")

            if command == 'login':
                self.login()
                break
            elif command == 'about':
                self.about()
            elif command == 'help':
                self.help()
            elif command == 'exit':
                self.charter = 'none'
                break
            else:
                print("Command not found! Please, try again.")

    def login(self):
        if path.exists('D:\\users.txt'):
            with open('D:\\users.txt', 'r') as file:
                users = [line.split(':') for line in file
                         if line[0:44] != '<username>:<password>:<blocked>:<limitation>']

            for _ in range(3):
                username = input("Login: ")
                password = input("Password: ")
                user_data = []
                for user in users:
                    if username == user[0]:
                        user_data = user
                if not user_data:
                    print("Such user is not registered in the system!")
                else:
                    if username == user_data[0] and user_data[2] == 'true':
                        print("This account is blocked! You cannot enter it.")
                        continue
                    elif password == user_data[1]:
                        if username == 'admin':
                            self.charter = 'admin'
                            self.name = 'admin'
                            break
                        else:
                            self.charter = 'user'
                            self.name = username
                            break
                    else:
                        print("Login or password incorrect!")
                        continue
            else:
                self.charter = 'none'
        else:
            with open('D:\\users.txt', 'w') as file:
                file.write("<username>:<password>:<blocked>:<limitation>\nadmin::false:false\n")
            print('The first login is recorded!\nLogged into the system as "admin" with an empty password.')
            self.charter = 'guest'
            self.name = 'guest'

    @staticmethod
    def about():
        print("""

  ┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃   Author    ┃   Stoliarchuk Vladyslav                                                                  ┃
  ┣━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
  ┃   Group     ┃   FB-81                                                                                  ┃
  ┣━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
  ┃   Variant   ┃   17                                                                                     ┃
  ┣━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
  ┃   Task      ┃   Password not matching username                                                         ┃                               
  ┗━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

        """)

    @staticmethod
    def help():
        print("""\

  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃                                         Available Commands                                             ┃
  ┣━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
  ┃             ┃ about - get information about the author                                                 ┃
  ┃ Guest level ┃ help - get information about available commands for each level                           ┃
  ┃             ┃ exit - exit the program                                                                  ┃
  ┃             ┃ login - log in                                                                           ┃
  ┣━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
  ┃ User level  ┃ change_pass - change your own user password                                              ┃
  ┣━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
  ┃             ┃ get_user_list - view the list of names of registered users and the settings set for them ┃
  ┃ Admin level ┃ add_user - add a unique new username to the list with empty password                     ┃
  ┃             ┃ block_user - blocking the ability of the user to work with the specified name            ┃
  ┃             ┃ limited_user_pass - enable or disable restrictions on user-selected passwords            ┃                                 
  ┗━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

              """)


class User(Guest):

    def menu(self):
        print('\nYou have a "User level"!')
        print('Enter "help" to get information about available commands for each level.')
        username = self.name
        with open('D:\\users.txt', 'r') as file:
            users = [line.split(':') for line in file]
        check = False
        index = None
        for user in range(len(users)):
            if username in users[user]:
                check = True
                index = user

        if check and users[index][3][:4] == 'true' and self.check_pass(username, users[index][1]):
            print("You have password limitation: \"password not matching username\".\nPlease, change your password!")
            self.change_pass()
        else:
            while True:
                command = input(f"┌──({self.name}@user) - [~|help|about|exit|login|change_pass|~]\n└─$ ")

                if command == 'login':
                    self.login()
                    break
                elif command == 'about':
                    self.about()
                elif command == 'help':
                    self.help()
                elif command == 'exit':
                    self.charter = 'none'
                    break
                elif command == 'change_pass':
                    self.change_pass()
                else:
                    print("Command not found! Please, try again")

    def change_pass(self):
        username = self.name
        with open('D:\\users.txt', 'r') as file:
            users = [line.split(':') for line in file]
        check = False
        index = None
        for user in range(len(users)):
            if username in users[user]:
                check = True
                index = user
        if check:
            while True:
                old_password = \
                    input('Please, write a password to change to a new one or write "quit" to quit!\nPassword: ')
                if old_password == users[index][1]:
                    while True:
                        new_password_first = input("New password: ")
                        new_password_second = input("Confirm new password: ")
                        new_pass_check = new_password_first == new_password_second

                        if users[index][3][:4] == 'true':
                            if new_pass_check and self.check_pass(username, new_password_first):
                                print("You have password limitation:\"password not matching username\"!\n"
                                      "Please, try again.")
                                continue
                            elif new_pass_check and not self.check_pass(username, new_password_first):
                                users[index][1] = new_password_second
                                new_users = [':'.join(user) for user in users]
                                new_users_str = ''.join(user for user in new_users)
                                with open('D:\\users.txt', 'w') as file:
                                    file.write(new_users_str)
                                print("Password changed successfully!")
                                break
                            else:
                                print("Passwords not matching! Try again.")
                        else:
                            if new_pass_check:
                                users[index][1] = new_password_second
                                new_users = [':'.join(user) for user in users]
                                new_users_str = ''.join(user for user in new_users)
                                with open('D:\\users.txt', 'w') as file:
                                    file.write(new_users_str)
                                print("Password changed successfully!")
                                break
                            else:
                                print("Passwords not matching! Try again.")
                                continue
                    break
                elif old_password == 'quit':
                    break
                else:
                    print("Incorrect password! Try again.")
                    continue
        else:
            print("User with this name does not exist!")

    @staticmethod
    def check_pass(username, password):
        return password == username


class Admin(User):

    def menu(self):
        print('\nYou have a "Admin level"!')
        print('Enter "help" to get information about available commands for each level.')

        while True:
            command = input(f"┌──({self.name}@admin) - [~|help|about|exit|login|change_pass|get_user_list|add_user"
                            f"|block_user|limited_user_pass|~]\n└─$ ")

            if command == 'login':
                self.login()
                break
            elif command == 'about':
                self.about()
            elif command == 'help':
                self.help()
            elif command == 'exit':
                self.charter = 'none'
                break
            elif command == 'change_pass':
                self.change_pass()
            elif command == 'get_user_list':
                self.get_user_list()
            elif command == 'add_user':
                self.add_user()
            elif command == 'block_user':
                self.block_user()
            elif command == 'limited_user_pass':
                self.limited_user_pass()
            else:
                print("Command not found! Please, try again")

    @staticmethod
    def get_user_list():
        with open('D:\\users.txt', 'r') as file:
            users = [line.split(':') for line in file]
        for user_data in users:
            print("{: >20} {: >20} {: >20} {: >20}".format(*user_data))

    @staticmethod
    def add_user():
        username = input("Enter the username of the new user: ")
        user_data = username + '::false:false\n'
        with open('D:\\users.txt', 'r+') as file:
            users = [line.split(':') for line in file if line[0:44] != '<username>:<password>:<blocked>:<limitation>']
            check = False
            for user in users:
                if username in user:
                    check = True
            if not check:
                file.write(user_data)
                print("Successfully added new user:", username)
            else:
                print("User with this name already exists!")

    @staticmethod
    def block_user():
        username = input("Enter the name of the user you want to block: ")
        with open('D:\\users.txt', 'r') as file:
            users = [line.split(':') for line in file]
        check = False
        index = None
        for user in range(len(users)):
            if username in users[user]:
                check = True
                index = user
        if check and users[index][2] == 'false':
            users[index][2] = 'true'
            new_users = [':'.join(user) for user in users]
            new_users_str = ''.join(user for user in new_users)
            with open('D:\\users.txt', 'w') as file:
                file.write(new_users_str)
            print(f"Successfully blocked user: {username}!")
        elif check and users[index][2] == 'true':
            users[index][2] = 'false'
            new_users = [':'.join(user) for user in users]
            new_users_str = ''.join(user for user in new_users)
            with open('D:\\users.txt', 'w') as file:
                file.write(new_users_str)
            print(f"Successfully unblocked user: {username}!")
        else:
            print("User with this name does not exist!")

    @staticmethod
    def limited_user_pass():
        username = input("Enter the name of the user you want to add limited: ")
        with open('D:\\users.txt', 'r') as file:
            users = [line.split(':') for line in file]
        check = False
        index = None
        for user in range(len(users)):
            if username in users[user]:
                check = True
                index = user
        if check and users[index][3][:5] == 'false':
            users[index][3] = 'true\n'
            new_users = [':'.join(user) for user in users]
            new_users_str = ''.join(user for user in new_users)
            with open('D:\\users.txt', 'w') as file:
                file.write(new_users_str)
            print(f"Successfully add limited to user: {username}!")
        elif check and users[index][3][:4] == 'true':
            users[index][3] = 'false\n'
            new_users = [':'.join(user) for user in users]
            new_users_str = ''.join(user for user in new_users)
            with open('D:\\users.txt', 'w') as file:
                file.write(new_users_str)
            print(f"Successfully remove limited to user: {username}!")
        else:
            print("User with this name does not exist!")


def main():
    charter = 'guest'
    name = 'guest'
    while True:
        if charter == 'guest':
            person = Guest(charter, name)
            charter = person.charter
            name = person.name
        elif charter == 'user':
            person = User(charter, name)
            charter = person.charter
            name = person.name
        elif charter == 'admin':
            person = Admin(charter, name)
            charter = person.charter
            name = person.name
        elif charter == 'none':
            break
        else:
            print("Admittance error!")


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


def verify(data):
    hash_data = SHA256.new()
    hash_data.update(data.encode())

    key_val = r"SOFTWARE\Stoliarchuk"
    registry_key = OpenKey(HKEY_CURRENT_USER, key_val, 0, KEY_QUERY_VALUE)
    signature = QueryValueEx(registry_key, "Signature")[0]
    print("Registry key value successfully get")
    CloseKey(registry_key)

    with open('D:\\log.pem', 'r') as file:
        pubkey = RSA.importKey(file.read())
    pkcs1_15.new(pubkey).verify(hash_data, signature)
    return True


if __name__ == '__main__':
    data = data_collection()
    print("Data collected:\n", data)
    if verify(data):
        print("Information is true. You can use this program!\n")
        main()
        input()
    else:
        print("Information is fake!")
        input()
