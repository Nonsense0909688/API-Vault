class APIVault {
  constructor(baseUrl) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.cookie = null;
  }

  async login(key) {
    const response = await fetch(`${this.baseUrl}/login/post`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ key }),
    });

    if (!response.ok) {
      throw new Error(`Login failed: ${response.status}`);
    }

    const cookie = response.headers.get("set-cookie");

    if (cookie) {
      this.cookie = cookie.split(";")[0];
    }

    return true;
  }

  async getSecrets() {
    const response = await fetch(`${this.baseUrl}/api/v1/secrets`, {
      headers: this.cookie ? { Cookie: this.cookie } : {},
    });

    if (!response.ok) {
      throw new Error(`Failed to retrieve secrets: ${response.status}`);
    }

    return response.json();
  }

  async logout() {
    if (!this.cookie) return;

    await fetch(`${this.baseUrl}/logout`, {
      headers: {
        Cookie: this.cookie,
      },
    });

    this.cookie = null;
  }
}

module.exports = APIVault;
