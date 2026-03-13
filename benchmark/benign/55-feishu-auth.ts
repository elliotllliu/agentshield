// Token management for Feishu API
const FEISHU_APP_ID = process.env.FEISHU_APP_ID;
const FEISHU_APP_SECRET = process.env.FEISHU_APP_SECRET;

export async function getAccessToken(): Promise<string> {
  const res = await fetch('https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      app_id: FEISHU_APP_ID,
      app_secret: FEISHU_APP_SECRET,
    }),
  });
  const data = await res.json();
  return data.tenant_access_token;
}

export async function refreshToken(): Promise<{ access_token: string; expires_in: number }> {
  const token = await getAccessToken();
  return { access_token: token, expires_in: 7200 };
}
