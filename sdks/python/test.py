from api_vault import APIVault

with APIVault("http://127.0.0.1:3000") as vault:

    login = vault.login("CHANGE_ME")
    print(vault.get_secrets())

    vault.save_secret("github", "abc")
    print(vault.get_secret("github"))

    vault.delete_secret("github")
    vault.logout()