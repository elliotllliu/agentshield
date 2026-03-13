// Simulated Feishu/Lark plugin — normal production code
// Should NOT trigger any security alerts

import { getAccessToken, refreshToken } from './auth';

// Normal fetch() API call to Feishu API
async function getDocContent(docId: string): Promise<string> {
  const token = await getAccessToken();
  const response = await fetch(`https://open.feishu.cn/open-apis/docx/v1/documents/${docId}`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });
  const data = await response.json();
  return data.content;
}

// Normal: send message via Feishu API
async function sendMessage(chatId: string, text: string) {
  const token = await getAccessToken();
  await fetch('https://open.feishu.cn/open-apis/im/v1/messages', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      receive_id: chatId,
      msg_type: 'text',
      content: JSON.stringify({ text }),
    }),
  });
}

// Normal: Excel column name conversion (A, B, C, ..., Z, AA, AB, ...)
function columnName(index: number): string {
  let name = '';
  while (index >= 0) {
    name = String.fromCharCode(65 + (index % 26)) + name;
    index = Math.floor(index / 26) - 1;
  }
  return name;
}

// Normal: token management with refresh
class TokenManager {
  private token: string = '';
  private expiresAt: number = 0;

  async getToken(): Promise<string> {
    if (Date.now() >= this.expiresAt) {
      const result = await refreshToken();
      this.token = result.access_token;
      this.expiresAt = Date.now() + result.expires_in * 1000;
    }
    return this.token;
  }
}

// Normal: cache with TTL
class Cache {
  private store = new Map<string, { value: any; expiry: number }>();

  set(key: string, value: any, ttlMs: number) {
    this.store.set(key, { value, expiry: Date.now() + ttlMs });
  }

  get(key: string): any {
    const entry = this.store.get(key);
    if (!entry || Date.now() > entry.expiry) {
      this.store.delete(key);
      return undefined;
    }
    return entry.value;
  }
}

export { getDocContent, sendMessage, columnName, TokenManager, Cache };
