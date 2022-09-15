# This is a sample Python script.

import crypt, re, os


# Idea: Read each line of the file and put it in a dictionary and check
# to see if it's a valid user before inserting.
def store_file_locally(filename):
    # Open the file if it exists, return error if no
    if not os.path.exists(filename):
        print(f"{filename} doesn't exist! Quitting...")
        exit()

    # File is valid. Open the file and creat dictionary
    shadow_file = open(filename)
    pw_dictionary = dict()

    # For every line in the file, split into attributes and insert into a dictionary
    # instead of reading for optimization
    for line in shadow_file:
        # Check to see if there is a valid user, then split and insert into dictionary
        if line.__contains__('crack'):

            each_text_line = re.split(r':', line)
            pw_dictionary.update({each_text_line[0]: each_text_line[1]})
    return pw_dictionary

def crack_passwords(dict):
    for cred in dict:
        print(cred)
        # username = cred
        # hashed_pw = cred[1]
        # test_pw = crypt.crypt("123456")
        # print(f"Username: {username}, user's pw: {hashed_pw}, test's pw: {test_pw}")


if __name__ == '__main__':
    print(f"Enter file name:")
    response = input();
    db = store_file_locally(response)
    crack_passwords(db)
