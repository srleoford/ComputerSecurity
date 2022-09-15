# This is a sample Python script.

import os
import re
from hashlib import md5


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

    # For every line in the file, split into attributes, insert into a dictionary
    # instead of reading for optimization, and return that dictionary
    for line in shadow_file:
        # Check to see if there is a valid user, then split and insert into dictionary
        if line.__contains__('crack'):
            each_text_line = re.split(r':', line)
            pw_dictionary.update({each_text_line[0]: each_text_line[1]})
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


def crack_passwords(dictionary):
    for cred in dictionary:
        username = cred
        hashed_pw = dictionary[cred]
        h = md5(b"123456")
        test_pw = h.hexdigest()
        print(f"Username: {username}, user's pw: {hashed_pw}, test's pw: {test_pw}")
        break


def compare_passwords(dictionary, db):
    result_dict = dict()
    for password in db:
        for cred in dictionary:
            username = cred
            hashed_pw = dictionary[cred]
            h = md5(password.encode('utf8'))
            test_pw = h.hexdigest()
            if test_pw == hashed_pw:
                result_dict.update({f'{username}': f'{test_pw}'})

    return result_dict


if __name__ == '__main__':
    # print(f"Enter shadow file name:")
    # print(f"Enter password file name:")
    # response = input();
    shadow_dict = store_shadow_file_locally("Assignment 1 for CS 4351/Problem 1/shadowfile.txt")
    common_db = store_passwords("Assignment 1 for CS 4351/Problem 1/commonPasswdFile.txt")
    common2_db = store_passwords("Assignment 1 for CS 4351/Problem 1/commonPasswordFile2.txt")
    result = compare_passwords(shadow_dict, common_db)
    print(result)
