# This is a sample Python script.
import os
import re
from passlib.hash import md5_crypt
import hashlib
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
        # For the sake of time, typically a password is at least larger than five characters long, so
        # only 'len(test_pw) > 5' will be tested

        # In case time is a factor, will try to limit pwd tests to len(test_pw) > 5.
        # if len(test_pw) < 5:
        #     continue

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

                    # If all the passwords were cracked, return 'cracked'.
                    if len(cracked) == len(dictionary):
                        print(f"Entire file is cracked!!! I'm done.")
                        return cracked
                    continue
                # print(f"Username: {username}, user's encrypted pw: {user['hashPW']}, test's pw: {test_pw}")
            else:
                # print(f"{username} is already cracked. Let's try the next one...")
                continue
    return cracked


def store_words(filename):
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
        if len(passwd[0]) > 5:
            pw_list.append(passwd[0])

    return pw_list


def create_passwords(stored_words):
    createdPWDS = dict()
    testing_word_passwords = dict()
    testing_number_passwords = dict()
    testing_word_number_passwords = dict()
    testing_double_word_passwords = dict()
    count = 1

    # Stores just dictionary words into the dictionary
    for word in stored_words:
        if 11 > len(word) > 5:
            testing_word_passwords.update({f"password{count}": word})
            count += 1
    createdPWDS.update(testing_word_passwords)

    # Stores just numbers into the dictionary
    for i in range(0, 100000000):
        if 11 > len(str(i)) > 5:
            testing_number_passwords.update({f"password{count}": str(i).zfill(1)})
            count += 1
    createdPWDS.update(testing_number_passwords)

    # Stores word/number combinations into the dictionary
    for word in stored_words:
        for n in range(10000):
            if 11 > len(word + str(n)) > 5:
                new_password = word + str(n)
                testing_word_number_passwords.update({f"password{count}": new_password})
                count += 1
    createdPWDS.update(testing_word_number_passwords)

    # Stores compound words into the dictionary
    for first_word in stored_words:
        for second_word in stored_words:
            new_password = first_word + second_word
            if 11 > len(new_password) > 5:
                testing_double_word_passwords.update({f"password{count}": new_password})
                count += 1
    createdPWDS.update(testing_double_word_passwords)

    return createdPWDS


def store_unsalted_table(filename):
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
        passwd = re.split(r'[\n:]', line)
        pw_list.append({f"{passwd[0]}": f"{passwd[1]}"})
    return pw_list


def store_salted_table(filename):
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
        passwd = re.split(r'[:\n]', line)
        pw_list.append({f"{passwd[0]}": {"salt": passwd[1], "hash": passwd[2]}})

    return pw_list


def crack_unsalted_passwords(test_words, unsalted_table):
    # Now that we have created all the possible passwords for the system, let's hash them to compare
    # with the hashes in the password files. First, the unsalted, then the salted hashes.
    cracked_users = dict()
    pwdCount = 1

    # Idea: Compare each 'test_words' against 'unsalted_table' and handle accordingly
    for key, passwd in test_words.items():
        userCount = 1

        # Compare every 'pw_hash' to every 'user' in the 'unsalted_table'
        for user in unsalted_table:
            # print(f"Testing {passwd} against {f'user{userCount}'}")
            # If 'user' is already in 'cracked_users', increment 'userCount' and continue.
            # Else, calculate the next 'pw_hash' to compare
            if cracked_users.get(f'user{userCount}') is not None:
                # print(f"user{userCount} has already been cracked...")
                userCount += 1
                continue

            pw_hash = hashlib.md5(passwd.encode()).hexdigest()

            # Here, 'user' is not cracked so compare 'pw_hash' to 'user'.
            # If there's a match, update 'cracked_users', increment 'userCount', and continue.
            # Else, increment 'userCount' and continue to next iteration.
            if user[f'user{userCount}'] == pw_hash:
                print(f"User cracked! {f'user{userCount}'}:{passwd}")
                cracked_users.update({f'user{userCount}': passwd})

                # If so, return cracked_users. Else, reset the 'userCount'
                if len(cracked_users) == len(unsalted_table):
                    print("All the users have been cracked form unsalted table!!!")
                    return cracked_users
                userCount += 1
                continue
            else:
                userCount += 1
                continue

        # Increment the 'pwdCount' for next password to test against 'passwd'
        pwdCount += 1

    # Everything has been tested, return users that was cracked in 'cracked_users'
    return cracked_users


def crack_salted_passwords(test_words, salted_table):
    # Now that we have created all the possible passwords for the system, let's hash them to compare
    # with the hashes in the password files. First, the unsalted, then the salted hashes.
    cracked_users = dict()
    pwdCount = 1

    # Idea: Compare each 'test_words' against 'unsalted_table' and handle accordingly
    for key, passwd in test_words.items():
        userCount = 1

        # Compare every 'pw_hash' to every 'user' in the 'unsalted_table'
        for user in salted_table:
            # If 'user' is already in 'cracked_users', increment 'userCount' and continue.
            # Else, calculate the next 'pw_hash' to compare
            if cracked_users.get(f'user{userCount}') is not None:
                # print(f"user{userCount} has already been cracked...")
                userCount += 1
                continue

            pw_hash = hashlib.md5(user[f'user{userCount}']['salt'].encode() + passwd.encode()).hexdigest()

            # Here, 'user' is not cracked so compare 'pw_hash' to 'user'.
            # If there's a match, update 'cracked_users', increment 'userCount', and continue.
            # Else, increment 'userCount' and continue to next iteration.
            if user[f'user{userCount}']['hash'] == pw_hash:
                print(f"User cracked! {f'user{userCount}'}:{passwd}")
                cracked_users.update({f'user{userCount}': passwd})
                # If so, return cracked_users. Else, reset the 'userCount'
                if len(cracked_users) == len(salted_table):
                    print("All the users have been cracked form unsalted table!!!")
                    return cracked_users
                userCount += 1
                continue
            else:
                userCount += 1
                continue

        # Increment the 'pwdCount' for next password to test against 'passwd'
        pwdCount += 1

    # Everything has been tested, return users that was cracked in 'cracked_users'
    return cracked_users


if __name__ == '__main__':
    # # Accepts input from the user in the form of <filename> path from root
    # print(f"Enter shadow file name:")
    # print(f"Enter password file name:")
    # response = input();

    # # This is the section for problem 1
    # # From response, read in the shadow file and then read in from stored command password files
    # shadow_dict = store_shadow_file_locally("Assignment 1 for CS 4351/Problem 1/shadowfile.txt")
    # common_db = store_passwords("Assignment 1 for CS 4351/Problem 1/commonPasswdFile.txt")
    # common2_db = store_passwords("Assignment 1 for CS 4351/Problem 1/commonPasswordFile2.txt")
    #
    # # Brute force attack on the shadow file. Returns dictionary of resulting accounts hacked
    # crackedPW = crack_passwords(shadow_dict, common_db)
    # crackedPW.update(crack_passwords(shadow_dict, common2_db))
    #
    # # Print result
    # result_problem1 = OrderedDict(sorted(crackedPW.items()))
    # print(f"The result of problem 1: ")
    # print(f"List of accounts:")
    # for user in result_problem1:
    #     print(user)
    # print(f"Number of accounts: {len(result_problem1)}")

    # Here's brute force attempt for problem 2
    words = store_words("Assignment 1 for CS 4351/Problem 2/words.txt")
    # unsaltedUsers = store_unsalted_table("Assignment 1 for CS 4351/Problem 2/UnsaltedPassTable.txt")
    saltedUsers = store_salted_table("Assignment 1 for CS 4351/Problem 2/SaltedPassTable.txt")
    testing_passwords = create_passwords(words)
    # unsalted_result = crack_unsalted_passwords(testing_passwords, unsaltedUsers)
    salted_result = crack_salted_passwords(testing_passwords, saltedUsers)

    # Print result
    # result_problem2a = OrderedDict(sorted(unsalted_result.items()))
    # print(f"The result of problem 2a: ")
    # print(f"List of accounts:")
    # for user in result_problem2a:
    #     print(f"Account: {user}, Password: {user.values()}")
    # print(f"Number of accounts: {len(result_problem2a)}")

    result_problem2b = OrderedDict(sorted(salted_result.items()))
    print(f"The result of problem 2b: ")
    print(f"List of accounts:")
    for user in result_problem2b:
        print(user)
    print(f"Number of accounts: {len(result_problem2b)}")



    # # This section is used for testing methods to ensure integrity
    # test = {'elf': {'name': "Elrond"}}
    # nottest = {'elf1': {"name": 'Galadriel'}}
    # nottest.update(test)
    # print(nottest)
