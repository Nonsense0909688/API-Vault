from api_vault import APIVault

USERNAME = "Admin" # Account username to enter as 
PASSWORD = "riT6iaAL5TaXfoxQP-Mk-hVo" # Account password

with APIVault("http://127.0.0.1:3000") as vault:

    login = vault.login(USERNAME, PASSWORD) # Logged in as the user if the password is correct
    # login should show {"authentication": true}
    
    QUERY = "testinbg" # The key we want to query for 
    print(vault.secrets.get(QUERY)) # Will return `None` if empty else will return the decrypted value
    
    print(vault.secrets.get_all()) # Will return all shared to or created_by the users (Only the names not the value)
    
    KEY = "GITHUB_TOKEN"
    VALUE = "......"
    vault.secrets.save(KEY, VALUE) # Will sve the API Key to the account storage
    
    KEY = "GITHUB_TOKEN"
    vault.secrets.delete(KEY) # WIll delete the API Key from the account storage
    
    vault.logout() # Finally logging out of the account