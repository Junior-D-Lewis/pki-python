from cryptography.hazmat.primitives import hashes
from register_CA.ae import register_authority
from root_CA.ca import sign_certificate

#Main, c'est dans cette fonction qu'il y aura des inter-act
if __name__ == '__main__':
    commonName = input("veuillez saisir votre  nom ? : ")
    organizationUnitName = input("veuillez saisir le nom de l'unité organisation ? ")
    hash_algo = int(input("Veuillez saisir quel algo de chiffrement et se signature a utiliser :"
                     "\nTaper 0 pour SHA256\n"
                     "Taper 1 pour SHA3_384\n"
                     "Taper 2 pour SHA224\n"
                     "Taper 3 pour SHA3_512\n"
                     "Taper 4 pour SHA512_224\n"
                     "Taper 5 pour SHA512_256\n"
                     "Taper 6 pour BLAKE2b\n"
                     "Taper 7 pour BLAKE2s\n"
                     "Taper 8 pour SM3\n"
                     "Taper 9 pour SHA1\n"
                     "Taper 10 pour SHA3_224\n"
                     "Taper 11 pour SHA3_256\n"
                     "Taper 12 pour SHA384\n"
                     "Taper 13 pour SHAKE128\n"
                     "Taper 14 pour MD5\n"
                     "Taper 15 pour SHAKE256\n"))

    unsigned_certificate = register_authority(commonName, organizationUnitName)
    sign_certificate(unsigned_certificate, hash_algo, "user_Certificate/"+organizationUnitName)


