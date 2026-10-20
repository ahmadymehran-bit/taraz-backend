export const config = { api: { bodyParser: false } };

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    // دریافت فایل از درخواست
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const buffer = Buffer.concat(chunks);

    if (!buffer || buffer.length === 0) {
      return res.status(400).json({ error: 'No file received' });
    }

    // تبدیل بافر به Blob برای ارسال به UUpload
    const blob = new Blob([buffer], { type: 'image/jpeg' });
    const formData = new FormData();
    formData.append('file', blob, 'image.jpg');

    // ارسال به UUpload
    const uploadRes = await fetch('https://uupload.ir/upload.php', {
      method: 'POST',
      body: formData
    });

    const result = await uploadRes.text();
    
    // UUpload لینک رو توی پاسخ برمی‌گردونه، اینجا سعی می‌کنیم لینک رو استخراج کنیم
    return res.status(200).json({ 
      ok: true, 
      raw: result,
      message: 'File sent to UUpload (check raw response)'
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
