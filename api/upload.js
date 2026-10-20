export const config = { api: { bodyParser: false } };

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const buffer = Buffer.concat(chunks);

    if (!buffer || buffer.length === 0) {
      return res.status(400).json({ error: 'No file received' });
    }

    const blob = new Blob([buffer], { type: 'image/jpeg' });
    const formData = new FormData();
    formData.append('file', blob, 'image.jpg');

    // ارسال به UUpload
    const uploadRes = await fetch('https://uupload.ir/upload.php', {
      method: 'POST',
      body: formData
    });

    const resultText = await uploadRes.text();
    
    // تلاش برای استخراج لینک از پاسخ UUpload (معمولاً لینک داخل تگ‌های HTML هست)
    const urlMatch = resultText.match(/https:\/\/uupload\.ir\/[^\s"']+/);
    const imageUrl = urlMatch ? urlMatch[0] : null;

    if (imageUrl) {
      return res.status(200).json({ ok: true, url: imageUrl });
    } else {
      // اگر لینک پیدا نشد، پاسخ خام رو برمی‌گردونیم تا دیباگ کنیم
      return res.status(200).json({ ok: true, url: null, raw: resultText.substring(0, 500) });
    }
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
