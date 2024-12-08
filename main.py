# CS 7530 Group Assignment
# Professor Zhang November 2024
# Sameer Jehan Nancy, Bhavya Nanga, Tyler Ebersold
# File for RSA authentication/encryption and decryption to be imported into driver file
# result: Contains the binary of the counter value
# first_key_3DES_binary: Contains the binary of the first key for 3DES
# second_key_3DES_binary: Contains the binary of the second key for 3DES
import plaintext_blocks
import rsa_auth

def binary_keys_generation(given_key):
    list_of_binaries = {
        "0": "0000",
        "1": "0001",
        "2": "0010",
        "3": "0011",
        "4": "0100",
        "5": "0101",
        "6": "0110",
        "7": "0111",
        "8": "1000",
        "9": "1001",
        "A": "1010",
        "B": "1011",
        "C": "1100",
        "D": "1101",
        "E": "1110",
        "F": "1111"
    }

    binary_key_result = ""

   
    if given_key.startswith("0x"):
        truncated_key = given_key[2:]
        for character in truncated_key: 
            if character in list_of_binaries:
                binary_key_result+=list_of_binaries[character]

    else:
        for character in given_key: 
            if character in list_of_binaries:
                binary_key_result+=list_of_binaries[character]



    return binary_key_result
        


def hexa_keys_generation(given_key):
    list_of_binaries = {
        "0000": "0",
        "0001": "1",
        "0010": "2",
        "0011": "3",
        "0100": "4",
        "0101": "5",
        "0110": "6",
        "0111": "7",
        "1000": "8",
        "1001": "9",
        "1010": "A",
        "1011": "B",
        "1100": "C",
        "1101": "D",
        "1110": "E",
        "1111": "F"
    }

    binary_key_result = ""

    chunks = [given_key[i:i + 4] for i in range(0, len(given_key), 4)]

    for character in chunks:
        if character in list_of_binaries:
            binary_key_result += list_of_binaries[character]

    return binary_key_result


###Expansion function #####
def expansion_function(binary_string_right):
    chunks = [binary_string_right[i:i + 4] for i in range(0, len(binary_string_right), 4)]
    return chunks


def expansion_box(binary_string):
    result = ""
    expansion_box = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]
    l1 = []
    for i in expansion_box:
        l1.append(binary_string[i - 1])

    final_expansion_string_48 = ""
    for value in l1:
        final_expansion_string_48 += value

    # print(final_expansion_string_48)

    return final_expansion_string_48


#####PC1 FOR KEYS################

def pc1_keys(binary_string):
    permuted_choice_p1_table = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]

    sample_result = []
    permuted_choice_key = ""

    for value in permuted_choice_p1_table:
        # print("Value: {}, Result: {}".format(value, first_key_3DES_binary[value-1]))
        sample_result.append(binary_string[value - 1])

    for i in sample_result:
        permuted_choice_key += i

    return permuted_choice_key


#####Left circular shift function for Round 1,2,9, 16
def left_circular_shifts(binary_string):
    mid_part_pc1_key = len(binary_string) // 2
    left_part_pc1_key = binary_string[:mid_part_pc1_key]
    right_part_pc1_key = binary_string[mid_part_pc1_key:]

    # print(left_part_pc1_key)
    # print(right_part_pc1_key)

    # print(len(left_part_pc1_key))

    # print(len(right_part_pc1_key))

    # Implement left circular shift by 1 bit for round 1, 2, 9, 16, for left and right parts of key after PC1
    left_circular_left_key = left_part_pc1_key[1:] + left_part_pc1_key[0]
    #  print(left_circular_left_key)

    left_circular_right_key = right_part_pc1_key[1:] + right_part_pc1_key[0]
    #   print(left_circular_right_key)

    # we will use the combined circular keys result for next round..important to note
    combined_circular_keys = left_circular_left_key + left_circular_right_key
    #    print(combined_circular_keys)

    # print(len(combined_circular_keys))

    return combined_circular_keys


#####left circular shift for other rounds where bits shift by two circular#############
def left_circular_shifts_2(binary_string):
    mid_part_pc1_key = len(binary_string) // 2
    left_part_pc1_key = binary_string[:mid_part_pc1_key]
    right_part_pc1_key = binary_string[mid_part_pc1_key:]

    # print(left_part_pc1_key)
    # print(right_part_pc1_key)

    # print(len(left_part_pc1_key))

    # print(len(right_part_pc1_key))

    # Implement left circular shift by 1 bit for round 1, 2, 9, 16, for left and right parts of key after PC1
    left_circular_left_key = left_part_pc1_key[2:] + left_part_pc1_key[0] + left_part_pc1_key[1]

    # print(left_circular_left_key)

    left_circular_right_key = right_part_pc1_key[2:] + right_part_pc1_key[0] + right_part_pc1_key[1]
    # print(left_circular_right_key)

    # we will use the combined circular keys result for next round..important to note
    combined_circular_keys = left_circular_left_key + left_circular_right_key
    # print(combined_circular_keys)

    # print(len(combined_circular_keys))

    return combined_circular_keys


###################################Right Circular Shifts################################################################3
def right_circular_shifts(binary_string):
    mid_part_pc1_key = len(binary_string) // 2
    left_part_pc1_key = binary_string[:mid_part_pc1_key]
    right_part_pc1_key = binary_string[mid_part_pc1_key:]

    # print(left_part_pc1_key)
    # print(right_part_pc1_key)

    # print(len(left_part_pc1_key))

    # print(len(right_part_pc1_key))

    # Implement left circular shift by 1 bit for round 1, 2, 9, 16, for left and right parts of key after PC1
    right_circular_left_key = left_part_pc1_key[len(left_part_pc1_key) - 1] + left_part_pc1_key[
                                                                              :len(left_part_pc1_key) - 1]

    # left_part_pc1_key[len(left_part_pc1_key)-1] + left_part_pc1_key[:len(left_part_pc1_key)-1]
    #  print(left_circular_left_key)

    right_circular_right_key = right_part_pc1_key[len(right_part_pc1_key) - 1] + right_part_pc1_key[
                                                                                 :len(right_part_pc1_key) - 1]
    #   print(left_circular_right_key)

    # we will use the combined circular keys result for next round..important to note
    combined_circular_keys = right_circular_left_key + right_circular_right_key
    #    print(combined_circular_keys)

    # print(len(combined_circular_keys))

    return combined_circular_keys


#####left circular shift for other rounds where bits shift by two circular#############
def right_circular_shifts_2(binary_string):
    mid_part_pc1_key = len(binary_string) // 2
    left_part_pc1_key = binary_string[:mid_part_pc1_key]
    right_part_pc1_key = binary_string[mid_part_pc1_key:]

    # print(left_part_pc1_key)
    # print(right_part_pc1_key)

    # print(len(left_part_pc1_key))

    # print(len(right_part_pc1_key))

    # Implement left circular shift by 1 bit for round 1, 2, 9, 16, for left and right parts of key after PC1

    right_circular_left_key = left_part_pc1_key[len(left_part_pc1_key) - 2] + left_part_pc1_key[
        len(left_part_pc1_key) - 1] + left_part_pc1_key[:len(left_part_pc1_key) - 2]
    # print(left_circular_left_key)

    right_circular_right_key = right_part_pc1_key[len(right_part_pc1_key) - 2] + right_part_pc1_key[
        len(right_part_pc1_key) - 1] + right_part_pc1_key[:len(right_part_pc1_key) - 2]
    # print(left_circular_right_key)

    # we will use the combined circular keys result for next round..important to note
    combined_circular_keys = right_circular_left_key + right_circular_right_key
    # print(combined_circular_keys)

    # print(len(combined_circular_keys))

    return combined_circular_keys


##############PC2 Implementation######################3
def permuated_choice_2(binary_string):
    permuted_choice_table_2 = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]

    permutated_choice_list = []
    permutated_choice_2_string = ""
    for value in permuted_choice_table_2:
        permutated_choice_list.append(binary_string[value - 1])

    for i in permutated_choice_list:
        permutated_choice_2_string += i

    # print("Before PC2: {}".format(binary_string))
    # print("Length Before PC2: {}".format(len(binary_string)))
    # print("PC2: {}".format(permutated_choice_2_string))

    return permutated_choice_2_string


#####XOR function implemented for expansion and pc2 key##################3
def xor_function_expansion_pc2_key(binary_string1, binary_string2):
    sample = ""
    sample = ''.join('1' if bs_1 != bs_2 else '0' for bs_1, bs_2 in zip(binary_string1, binary_string2))
    return sample


#####################sub box###############################

def sub_boxes(row, column, index):
    sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

            [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
             [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
             [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
             [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

            [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
             [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
             [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
             [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

            [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
             [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
             [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
             [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

            [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
             [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
             [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
             [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

            [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
             [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
             [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],

             [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

            [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
             [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
             [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
             [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

            [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
             [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
             [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
             [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

    return sbox[index][row][column]


def substituion_boxes(binary_string):
    chunks = [binary_string[i:i + 6] for i in range(0, len(binary_string), 6)]

    # Create the first list with the first and last characters of each string
    list1 = [s[0] + s[-1] for s in chunks]

    # Create the second list with the middle 4 characters of each string
    list2 = [s[1:5] for s in chunks]

    # Print the results
    # print(chunks)
    # print("List 1:", list1)
    # print("List 2:", list2)

    # Use the below list for substitution boxes
    row_values = [int(num, 2) for num in list1]
    # print(row_values)

    column_values = [int(num, 2) for num in list2]
    # print(column_values)

    # substituion_boxes(row_values[0], column_values[0], 0)# 3rd row and 6th column
    # run above function for rest of the chunks
    # convert 1 to 4 bit binary
    # apply permutation

    # for loop for sub boxes to loop through all 8 chunks
    sub_list = []
    for index, value in enumerate(row_values):
        # print("ndex: {}, Value: {}".format(index, value))
        # print("ndex: {}, Value: {}".format(index, column_values[index]))
        sub_list.append((sub_boxes(value, column_values[index], index)))  # 3rd row and 6th column

    sub_binary_list = []
    sub_binary_string = ""

    for value in sub_list:
        sub_binary_list.append(format(value, '04b'))

    for value in sub_binary_list:
        sub_binary_string += str(value)

    return sub_binary_string


####substituion boxes above###########################

##############permutation after substitution#############33
def permutation_box_end_f_function(sbox_list):
    permutation_box = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25

    ]

    result = ""
    for val in sbox_list:
        result += val

    permuted_string = ""
    for val in permutation_box:
        permuted_string += result[val - 1]

    return permuted_string


#########final step of round##################

def xor_and_combine(right_part, left_part, permuted_string):
    right_final_string = ''.join('1' if bs_1 != bs_2 else '0' for bs_1, bs_2 in zip(left_part, permuted_string))

    round_string = right_part + right_final_string

    return round_string


def increment_binary(binary_str):

    bit_carry = 1
    result = ""

    for bit in reversed(binary_str):
        if bit == '0' and bit_carry == 1:
            result = '1' + result
            bit_carry = 0
        elif bit == '1' and bit_carry == 1:
            result = '0' + result
        else:
            result = bit + result

    if bit_carry == 1:
        result = '1' + result

    return result



def xor_cipher_plaintext(string1, string2):
    sample = ""
    sample = ''.join('1' if bs_1 != bs_2 else '0' for bs_1, bs_2 in zip(string1, string2))
    return sample


################################################################
###Above f function#############################################


def encryption_function_1(counter_value_binary, first_key_3DES_binary):
    mid_part = len(counter_value_binary) // 2
    left_part = counter_value_binary[:mid_part]
    right_part = counter_value_binary[mid_part:]

    #######expansion function###############

    # print("Before Expansion: {}".format(right_part))
    # print("Before Expansion String Length: {}".format(len(right_part)))
    expansion_string_48 = expansion_box(right_part)
    # print("After Expansion: {}".format(expansion_string_48))
    # print("After Expansion String Length: {}".format(len(expansion_string_48)))

    ###########key scheduling########################

    # PC1

    # print("First key des: {}".format(first_key_3DES_binary))
    # print("Length First key des: {}".format(len(first_key_3DES_binary)))
    pc1_key_des = pc1_keys(first_key_3DES_binary)
    # print("After PC1 transformation: {}".format(pc1_key_des))
    # print("Length PC1 key des: {}".format(len(pc1_key_des)))

    ###############Left circular shift##################
    circular_shift_key = ""
    # print(circular_shift_key)

    #################permuted choice 2##################3
    permutated_choice_2_key = ""
    extra_key = ""
    # from here the key will go to next rounds#implement loop for round 1 to 16.
    # For round 1,2,9,16 use ls1 function, for other rounds use ls2 function
    # generate 16 round keys

    # print(pc1_key_des)

    # okay left circuluar shift des working correct now work for another round

    ##############round implementation first key 3des##############################
    first_round_key_left_circular = left_circular_shifts(pc1_key_des)

    print("Round 1 Key Circular: {}".format(first_round_key_left_circular))
    permutated_choice_2_key = permuated_choice_2(first_round_key_left_circular)
    print("Round 1 Key Permutation: {}".format(permutated_choice_2_key))

    extra_key = first_round_key_left_circular

    keys = {}

    circular_shift_extra_key = ""

    keys[1] = extra_key

    for i in range(2, 17):
        print("Round: {}".format(i))
        if i == 2:
            keys[i] = left_circular_shifts(extra_key)
            extra_key = keys[2]

            keys[i + 1] = left_circular_shifts(extra_key)
            extra_key = keys[3]
            continue

        if i == 9 or i == 16:
            circular_shift_extra_key = left_circular_shifts(extra_key)
            keys[i + 1] = circular_shift_extra_key
            extra_key = circular_shift_extra_key
            continue

        else:
            circular_shift_extra_key_2 = left_circular_shifts_2(extra_key)
            keys[i + 1] = circular_shift_extra_key_2
            extra_key = circular_shift_extra_key_2

            continue

    permutated_choice_list = []

    for val in keys.values():
        print(val)

    for val in keys.values():
        permutated_choice_list.append(permuated_choice_2(val))

    print("Checking with permutation keys:")
    print(permutated_choice_2_key)

    print("check with second")
    print(permutated_choice_list)

    # XOR function between expansion and pc2-key
    xor_key_before_substitution = xor_function_expansion_pc2_key(expansion_string_48, permutated_choice_2_key)
    # print(xor_key_before_substitution)

    # print(len(xor_key_before_substitution))

    ####SUBSTITUTION BOX LOGIC######

    sbox_list = substituion_boxes(xor_key_before_substitution)
    # print("Sboxes")
    # print(sbox_list)

    ############permutation########################3

    permuted_string_final = permutation_box_end_f_function(sbox_list)
    # print("P")
    # print(permuted_string_final)

    final_string = xor_and_combine(right_part, left_part, permuted_string_final)
    # print("f")
    # print(final_string)

    ##start working on logic for rest of rounds, we already have PC2 keys

    # start working from round 2
    for i in range(2, 17):
        # print("Round: {}".format(i))
        mid_part = len(final_string) // 2
        left_part = final_string[:mid_part]
        right_part = final_string[mid_part:]

        # print("Right Part: {}".format(right_part))
        # print("Length: {}".format(len(right_part)))

        expansion_string_48 = expansion_box(right_part)
        # print("Expansion String: {}".format(expansion_string_48))
        # print(len(expansion_string_48))

        # print("Permutated choice: {}".format(permutated_choice_list[i]))

        xor_key_before_substitution = xor_function_expansion_pc2_key(expansion_string_48, permutated_choice_list[i])
        # print("XOR KEY")
        # print(xor_key_before_substitution)
        # print("Length of XOR key: {}".format(len(xor_key_before_substitution)))

        sbox_list = substituion_boxes(xor_key_before_substitution)

        # print("Subs len: {}".format(len(sbox_list)))
        # print("Permuted Final")
        permuted_string_final = permutation_box_end_f_function(sbox_list)
        # print(permuted_string_final)

        final_string = xor_and_combine(right_part, left_part, permuted_string_final)
        # print("Final String")
        # print(final_string)

        continue

    # swapping function
    mid_part_final_string = len(final_string) // 2
    left_part_final_string = final_string[:mid_part_final_string]
    right_part_final_string = final_string[mid_part_final_string:]

    right_part_final_string = left_part_final_string
    left_part_final_string = right_part_final_string

    # encrypted counter
    end_round_string = left_part_final_string + right_part_final_string
    print(len(end_round_string))
    print("Round 1-16: {}".format(end_round_string))
    print(len(end_round_string))

    print(hexa_keys_generation(end_round_string))

    return end_round_string


def decryption_function(end_round_string, second_key_3DES_binary):
    counter_value_binary = ""
    # decrypted counter#################################################################3
    second_counter_value = end_round_string
    counter_value_binary = second_counter_value

    mid_part = len(counter_value_binary) // 2
    left_part = counter_value_binary[:mid_part]
    right_part = counter_value_binary[mid_part:]

    # we have to use this key:
    #####################################second key des binary#################################

    expansion_string_48 = expansion_box(right_part)
    pc1_key_des = pc1_keys(second_key_3DES_binary)

    circular_shift_key = ""
    # print(circular_shift_key)

    permutated_choice_2_key = ""
    extra_key = ""

    ##############round implementation first key 3des##############################
    first_round_key_left_circular = left_circular_shifts(pc1_key_des)

    print("Round 1 Key Circular: {}".format(first_round_key_left_circular))
    permutated_choice_2_key = permuated_choice_2(first_round_key_left_circular)
    print("Round 1 Key Permutation: {}".format(permutated_choice_2_key))

    extra_key = first_round_key_left_circular

    keys = {}

    circular_shift_extra_key = ""

    keys[1] = extra_key
    #############################2nd key des###########################3
    print("Second Key Round Circular Shifts")

    for i in range(2, 17):
        print("Round: {}".format(i))
        if i == 2:
            keys[i] = left_circular_shifts(extra_key)
            extra_key = keys[2]

            keys[i + 1] = left_circular_shifts(extra_key)
            extra_key = keys[3]
            continue

        if i == 9 or i == 16:

            circular_shift_extra_key = left_circular_shifts(extra_key)
            keys[i + 1] = circular_shift_extra_key
            extra_key = circular_shift_extra_key
            continue

        else:
            circular_shift_extra_key_2 = left_circular_shifts_2(extra_key)
            keys[i + 1] = circular_shift_extra_key_2
            extra_key = circular_shift_extra_key_2

            continue

    print("Left Circular Shift values")

    permutated_choice_list = []

    for val in keys.values():
        print(val)

    for val in keys.values():
        permutated_choice_list.append(permuated_choice_2(val))

    # print("Right circular shift keys")

    print("Permuted Keys List Left########################################################")
    print(permutated_choice_list)
    print("Last permuted value: {}".format(permutated_choice_list[16]))

    permutated_choice_list_2_for_right = []
    permutated_choice_list_2_for_right.append(permutated_choice_list[16])

    # apply right circular shift on llast key round which is the extra_key above assign it to a a dictionary of right key
    first_round_key_right_circular = right_circular_shifts(extra_key)
    right_keys = {}
    circular_shift_extra_key_right = ""
    extra_key = first_round_key_right_circular

    right_keys[1] = extra_key

    for i in range(2, 17):
        # print("Round: {}".format(i))
        if i == 2:
            right_keys[i] = right_circular_shifts(extra_key)
            extra_key = right_keys[2]

            right_keys[i + 1] = right_circular_shifts(extra_key)
            extra_key = right_keys[3]
            continue

        if i == 9 or i == 16:
            circular_shift_extra_key_right = right_circular_shifts(extra_key)
            right_keys[i + 1] = circular_shift_extra_key_right
            extra_key = circular_shift_extra_key_right
            continue

        else:
            circular_shift_extra_key_right = right_circular_shifts_2(extra_key)
            right_keys[i + 1] = circular_shift_extra_key_right
            extra_key = circular_shift_extra_key_right

        continue

    # Right Keys: ################

    print("Right Circular Shift values")
    for val in right_keys.values():
        print(val)

    # print("Round 16: {}".format(right_keys[16]))

    for val in right_keys.values():
        permutated_choice_list_2_for_right.append(permuated_choice_2(val))

    print("Permutated choice keys Right")
    print(permutated_choice_list)

    # this the permutation for the 15th round for right circular shift
    fifteenth_round_rs = permutated_choice_list_2_for_right[16]

    ##############################################################################################33
    # XOR function between expansion and pc2-key
    xor_key_before_substitution = xor_function_expansion_pc2_key(expansion_string_48, fifteenth_round_rs)

    sbox_list = substituion_boxes(xor_key_before_substitution)

    ############permutation########################3

    permuted_string_final = permutation_box_end_f_function(sbox_list)
    # print("P")
    # print(permuted_string_final)

    final_string = xor_and_combine(right_part, left_part, permuted_string_final)
    # print("f")
    # print(final_string)

    print("final string rounds: {}".format(final_string))

    ##start working on logic for rest of rounds, we already have PC2 keys

    # start working from round 2
    for i in range(2, 17):
        # print("Round: {}".format(i))
        mid_part = len(final_string) // 2
        left_part = final_string[:mid_part]
        right_part = final_string[mid_part:]

        # print("Right Part: {}".format(right_part))
        # print("Length: {}".format(len(right_part)))

        expansion_string_48 = expansion_box(right_part)
        # print("Expansion String: {}".format(expansion_string_48))
        # print(len(expansion_string_48))

        # print("Permutated choice: {}".format(permutated_choice_list[i]))

        xor_key_before_substitution = xor_function_expansion_pc2_key(expansion_string_48, permutated_choice_list[i])
        # print("XOR KEY")
        # print(xor_key_before_substitution)
        # print("Length of XOR key: {}".format(len(xor_key_before_substitution)))

        sbox_list = substituion_boxes(xor_key_before_substitution)

        # print("Subs len: {}".format(len(sbox_list)))
        # print("Permuted Final")
        permuted_string_final = permutation_box_end_f_function(sbox_list)
        # print(permuted_string_final)

        final_string = xor_and_combine(right_part, left_part, permuted_string_final)
        # print("Final String: {}".format(final_string))
        # print(final_string)

        continue

    # swapping function
    mid_part_final_string = len(final_string) // 2
    left_part_final_string = final_string[:mid_part_final_string]
    right_part_final_string = final_string[mid_part_final_string:]

    right_part_final_string = left_part_final_string
    left_part_final_string = right_part_final_string

    # encrypted counter
    end_round_string = left_part_final_string + right_part_final_string
    # print(len(end_round_string))
    # print("Round 1-16: {}".format(end_round_string))
    # print(len(end_round_string))

    # print(hexa_keys_generation(end_round_string))
    #######################################################################33

    return end_round_string


def encryption_function_2(counter_value_binary, third_key_3DES_binary):
    mid_part = len(counter_value_binary) // 2
    left_part = counter_value_binary[:mid_part]
    right_part = counter_value_binary[mid_part:]

    #######expansion function###############

    # print("Before Expansion: {}".format(right_part))
    # print("Before Expansion String Length: {}".format(len(right_part)))
    expansion_string_48 = expansion_box(right_part)
    # print("After Expansion: {}".format(expansion_string_48))
    # print("After Expansion String Length: {}".format(len(expansion_string_48)))

    ###########key scheduling########################

    # PC1

    # print("First key des: {}".format(first_key_3DES_binary))
    # print("Length First key des: {}".format(len(first_key_3DES_binary)))
    pc1_key_des = pc1_keys(third_key_3DES_binary)
    # print("After PC1 transformation: {}".format(pc1_key_des))
    # print("Length PC1 key des: {}".format(len(pc1_key_des)))

    ###############Left circular shift##################
    circular_shift_key = ""
    # print(circular_shift_key)

    #################permuted choice 2##################3
    permutated_choice_2_key = ""
    extra_key = ""
    # from here the key will go to next rounds#implement loop for round 1 to 16.
    # For round 1,2,9,16 use ls1 function, for other rounds use ls2 function
    # generate 16 round keys

    # print(pc1_key_des)

    # okay left circuluar shift des working correct now work for another round

    ##############round implementation first key 3des##############################
    first_round_key_left_circular = left_circular_shifts(pc1_key_des)

    print("Round 1 Key Circular: {}".format(first_round_key_left_circular))
    permutated_choice_2_key = permuated_choice_2(first_round_key_left_circular)
    print("Round 1 Key Permutation: {}".format(permutated_choice_2_key))

    extra_key = first_round_key_left_circular

    keys = {}

    circular_shift_extra_key = ""

    keys[1] = extra_key

    for i in range(2, 17):
        print("Round: {}".format(i))
        if i == 2:
            keys[i] = left_circular_shifts(extra_key)
            extra_key = keys[2]

            keys[i + 1] = left_circular_shifts(extra_key)
            extra_key = keys[3]
            continue

        if i == 9 or i == 16:
            circular_shift_extra_key = left_circular_shifts(extra_key)
            keys[i + 1] = circular_shift_extra_key
            extra_key = circular_shift_extra_key
            continue

        else:
            circular_shift_extra_key_2 = left_circular_shifts_2(extra_key)
            keys[i + 1] = circular_shift_extra_key_2
            extra_key = circular_shift_extra_key_2

            continue

    permutated_choice_list = []

    for val in keys.values():
        print(val)

    for val in keys.values():
        permutated_choice_list.append(permuated_choice_2(val))

    print("Checking with permutation keys:")
    print(permutated_choice_2_key)

    print("check with second")
    print(permutated_choice_list)

    # XOR function between expansion and pc2-key
    xor_key_before_substitution = xor_function_expansion_pc2_key(expansion_string_48, permutated_choice_2_key)
    # print(xor_key_before_substitution)

    # print(len(xor_key_before_substitution))

    ####SUBSTITUTION BOX LOGIC######

    sbox_list = substituion_boxes(xor_key_before_substitution)
    # print("Sboxes")
    # print(sbox_list)

    ############permutation########################3

    permuted_string_final = permutation_box_end_f_function(sbox_list)
    # print("P")
    # print(permuted_string_final)

    final_string = xor_and_combine(right_part, left_part, permuted_string_final)
    # print("f")
    # print(final_string)

    ##start working on logic for rest of rounds, we already have PC2 keys

    # start working from round 2
    for i in range(2, 17):
        # print("Round: {}".format(i))
        mid_part = len(final_string) // 2
        left_part = final_string[:mid_part]
        right_part = final_string[mid_part:]

        # print("Right Part: {}".format(right_part))
        # print("Length: {}".format(len(right_part)))

        expansion_string_48 = expansion_box(right_part)
        # print("Expansion String: {}".format(expansion_string_48))
        # print(len(expansion_string_48))

        # print("Permutated choice: {}".format(permutated_choice_list[i]))

        xor_key_before_substitution = xor_function_expansion_pc2_key(expansion_string_48, permutated_choice_list[i])
        # print("XOR KEY")
        # print(xor_key_before_substitution)
        # print("Length of XOR key: {}".format(len(xor_key_before_substitution)))

        sbox_list = substituion_boxes(xor_key_before_substitution)

        # print("Subs len: {}".format(len(sbox_list)))
        # print("Permuted Final")
        permuted_string_final = permutation_box_end_f_function(sbox_list)
        # print(permuted_string_final)

        final_string = xor_and_combine(right_part, left_part, permuted_string_final)
        # print("Final String")
        # print(final_string)

        continue

    # swapping function
    mid_part_final_string = len(final_string) // 2
    left_part_final_string = final_string[:mid_part_final_string]
    right_part_final_string = final_string[mid_part_final_string:]

    right_part_final_string = left_part_final_string
    left_part_final_string = right_part_final_string

    # encrypted counter
    end_round_string = left_part_final_string + right_part_final_string
    print(len(end_round_string))
    print("Round 1-16: {}".format(end_round_string))
    print(len(end_round_string))

    print(hexa_keys_generation(end_round_string))

    return end_round_string

plaintext_block = []
plaintext_block = plaintext_blocks.generate_plaintext_blocks()
for block in plaintext_block:
    print("Plaintext: ", block)
# implement a loop to handle counter

# 3des 1st key
first_key_3des = "0x1A2B3C4D5E6F7890"
first_key_3DES_binary = binary_keys_generation(first_key_3des)

# 3DES 2nd key
second_key_des = "0x1B2C3D4E5F6A7B89"
second_key_3DES_binary = binary_keys_generation(second_key_des)

# 3DES 3rd key

third_key_des = "0xC1D2E3F4A5B6C7D8"
third_key_3DES_binary = binary_keys_generation(third_key_des)

# first convert the key to binary 64 bits
counter_value = "0x0123456789ABCDEF"
counter_value_binary = binary_keys_generation(counter_value)

xorred_plaintext = []

for i in range(len(plaintext_block)):
    print("Round: {}".format(i))
    print("first counter: {}".format(counter_value_binary))

    print(len(counter_value_binary))
    encryption_first_string = encryption_function_1(counter_value_binary, first_key_3DES_binary)
    decryption_string = decryption_function(encryption_first_string, second_key_3DES_binary)
    encryption_last_string = encryption_function_2(decryption_string, third_key_3DES_binary)
    xorred_string = xor_cipher_plaintext(plaintext_block[i], encryption_last_string)
    xorred_plaintext.append(xorred_string)
    

    counter_incremented = increment_binary(counter_value_binary)
    print("Counter Incremented: {}".format(len(counter_incremented)))
    counter_value_binary = str(counter_incremented)
    # counter_value_binary = counter_incremented

print("XORRED PLAINTEXT")
print(xorred_plaintext)

print(hexa_keys_generation(xorred_plaintext[1]))

for val in xorred_plaintext: 
    print(hexa_keys_generation(val))

################RSA Authenticate###################
post = []
def RSA_auth():
    for value in xorred_plaintext:
        post.append(rsa_auth.authenticate(value))




###start working on logic for rest of rounds, we already have PC2 keys
##################Importing Binary Plaintext Blocks##########################
RSA_auth()

##################Writing Encrypted blocks to encrypted_message.txt##########################
file2 = open('encrypted_message.txt', 'w')
def write_encrypted():
    for value in xorred_plaintext:
        print(value)
        file2.write(hexa_keys_generation(value))

write_encrypted()
