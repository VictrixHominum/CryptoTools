import base64


def pem_decoder(path_to_pem):
    with open(path_to_pem) as f:
        data = f.read()

    data = bytes(data[30:-30].encode("ascii"))
    hexData = base64.decodebytes(data).hex()

    ID = {
        "INTEGER":          0x02,
    }

    NAME = {}

    for i in ID:
        NAME[ID[i]] = i

    # An RSA private key shall have ASN.1 type RSAPrivateKey:
    #
    #    RSAPrivateKey ::= SEQUENCE {
    #      version Version,
    #      modulus INTEGER, -- n
    #      publicExponent INTEGER, -- e
    #      privateExponent INTEGER, -- d
    #      prime1 INTEGER, -- p
    #      prime2 INTEGER, -- q
    #      exponent1 INTEGER, -- d mod (p-1)
    #      exponent2 INTEGER, -- d mod (q-1)
    #      coefficient INTEGER -- (inverse of q) mod p }
    #
    #    Version ::= INTEGER

    typeArray = ["Version", "Modulus", "Public Exponent", "Private Exponent", "Prime 1", "Prime 2", "Exponent 1",
                 "Exponent 2", "Coefficient"]

    lengthArray = ["(Octets)", "(Octets)", "(Hex)", "(Octets)", "(Octets)", "(Octets)", "(Octets)", "(Octets)",
                   "(Octets)"]

    valueArray = ["", "-n", "-e", "-d", "-p", "-q", "- d mod (p-1)", "- d mod (q-1)", "- q^-1 mod p"]

    def lengthInOctets(x, y):
        return int(hexData[x:y], 16)

    print("\nConfirm length of hexData matches length value in ASN.1: " + str(len(hexData) ==
                                                                              (int(hexData[4:8], 16)*2) + 8))
    # The '+8' is to account for the 8 bits at the start that the ASN.1 length doesn't include
    print("------------------------------------------------------------------------------------------- \n")

    x, y = 4, 8
    print("Sequence {")
    print("\tLength of Sequence: " + str(int(hexData[x:y], 16)*2))  # We can skip out bits 0-3 as we know they will
    # be 3082

    x += 4
    y += 2

    for loop in range(0, 9):

        print("\t\t" + typeArray[loop] + " Type: " + NAME[int(hexData[x:y], 16) & 31])  # I confirm type everytime as
        # more of a debug as it easily shows if we're in the wrong place

        x += 2
        y += 2
        if int(hexData[x:y], 16) == int(0x82):
            x += 2
            y += 4
            len_in_octs = lengthInOctets(x, y)

        elif int(hexData[x:y], 16) == int(0x81):

            x += 2
            y += 2
            len_in_octs = lengthInOctets(x, y)

        else:
            len_in_octs = lengthInOctets(x, y)

        print("\t\t\t" + typeArray[loop] + " Length " + lengthArray[loop] + ": " + str(len_in_octs))

        x = y
        y += len_in_octs * 2

        print("\t\t\t" + typeArray[loop] + " " + valueArray[loop] + " (Value): " + hexData[x:y])

        x = y
        y += 2

        print("------------------------------------------\n")

    print("                                     }")


pem_decoder("./pem.pem")
