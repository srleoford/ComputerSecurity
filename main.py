# This is a sample Python script.
import os
import re
from passlib.hash import md5_crypt
from collections import OrderedDict


# Idea: Read each line of the file and put it in a dictionary and check
# to see if it's a valid user before inserting.
def store_shadow_file_locally(filename):
    # Open the file if it exists, return error if no
    if not os.path.exists(filename):
        print(f"{filename} doesn't exist! Quitting...")
        exit()

    # File is valid. Open the file and creat dictionary
    shadow_file = open(filename)
    pw_dictionary = dict()
    count = 0

    # For every line in the file, split into attributes, insert into a dictionary
    # instead of reading for optimization, and return that dictionary
    for line in shadow_file:
        # Check to see if there is a valid user, then split and insert into dictionary
        if line.__contains__('crack'):
            each_text_line = re.split(r':', line)
            pw_dictionary.update({f"user{count}": {"username": each_text_line[0], "hashPW": each_text_line[1],
                                                   "last_PW_changed": each_text_line[2],
                                                   "min_PW_age": each_text_line[3], "max_PW_age": each_text_line[4],
                                                   "warn_period": each_text_line[5]}})
            count += 1
    return pw_dictionary


# Store all the passwords locally to use for comparison
def store_passwords(filename):
    # Open the file if it exists, return error if no
    if not os.path.exists(filename):
        print(f"{filename} doesn't exist! Quitting...")
        exit()

    # File is valid. Open the file and creat dictionary
    password_file = open(filename)
    pw_list = list()

    # For every line in the file, split into attributes, insert into a dictionary
    # instead of reading for optimization, and return that dictionary
    for line in password_file:
        # Check to see if there is a valid user, then split and insert into dictionary
        passwd = re.split(r'\n', line)
        pw_list.append(passwd[0])
    return pw_list


# Idea: Grab each test password and compare it against the password file.
# If a password was cracked, remove it from the password file and store it
# in a cracked dictionary. Furthermore, once a password is cracked, check if the
# password was used again in the rest of the password file to remove duplicates
def crack_passwords(dictionary, test_db):
    cracked = dict()
    # Take each password and brute force against the password file
    for test_pw in test_db:
        # Each account is a dictionary with each attribute for each account (username, encrypted PW, etc.)
        # Take encrypted password and split it into type, salt, and hash for use into the MD5 encryption
        # If the account has been hacked (is in 'cracked' dictionary), get to the next OR if all the passwords
        # are cracked (as many items in 'cracked' as in shadow file) return 'cracked'.

        # If all the passwords were cracked, return 'cracked'.
        if len(cracked) == len(dictionary):
            print(f"Entire file is cracked!!! I'm done.")
            return cracked

        for account in dictionary:
            user = dictionary[account]
            username = user['username']

            # If user hasn't been cracked, try to crack it.
            if cracked.get(username) is None:
                tsh_format = re.split(r'\$', user['hashPW'])
                password_info = {'type': tsh_format[1], 'salt': tsh_format[2], 'hash': tsh_format[3]}
                test_hash = md5_crypt.using(salt=password_info['salt']).hash(test_pw)
                # print(f"Testing password {test_pw} on {username} by comparing {test_hash} and {user['hashPW']}...")
                if test_hash == user['hashPW']:
                    print(f"Account cracked! {username}:{test_pw}")
                    cracked.update({f'{username}': f'{test_pw}'})
                    # print(f"Passwords cracked so far...{cracked}")
                    continue
                # print(f"Username: {username}, user's encrypted pw: {user['hashPW']}, test's pw: {test_pw}")
            else:
                # print(f"{username} is already cracked. Let's try the next one...")
                continue
    return cracked


if __name__ == '__main__':
    # print(f"Enter shadow file name:")
    # print(f"Enter password file name:")
    # response = input();
    shadow_dict = store_shadow_file_locally("Assignment 1 for CS 4351/Problem 1/shadowfile.txt")
    common_db = store_passwords("Assignment 1 for CS 4351/Problem 1/commonPasswdFile.txt")
    common2_db = store_passwords("Assignment 1 for CS 4351/Problem 1/commonPasswordFile2.txt")
    # result = compare_passwords(shadow_dict, common_db)
    crackedPW = crack_passwords(shadow_dict, common_db)
    crackedPW.update(crack_passwords(shadow_dict, common2_db))
    # print(result_crack1)
    # print(result_crack2)
    # test = {'elf': "Elrond"}
    # nottest = {'elf1': "Galadriel", 'elf3': 'Legolas'}
    # nottest.update(test)
    result = OrderedDict(sorted(crackedPW.items()))
    print(result)
