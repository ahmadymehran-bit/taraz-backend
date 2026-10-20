export const config = { api: { bodyParser: false } };

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    // اینجا ما فایل رو از فرم دریافت می‌کنیم
    // نکته: برای سادگی، فعلاً یک پیام تستی برمی‌گردونیم تا اتصال رو چک کنیم
    return res.status(200).json({ 
      ok: true, 
      message: 'Upload API is ready',
      note: 'For real upload, we will integrate the service in the next step'
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
