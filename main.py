from database import create_tables



def main():
    print("=============================================" )    
    print("         ======= 🔐Safe Vault ======= "       )
    print("=============================================" )


    print(" database id starting... ")

    create_tables()


    print(" database successfully created. ")
    print(" SafeVault is ready ! ")


if __name__ == "__main__":
    main()

    