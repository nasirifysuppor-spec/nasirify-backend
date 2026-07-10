const express = require('express');
const cors = require('cors');
const dns = require('dns');
const axios = require('axios');
require('dotenv').config();

// IPv4 کو ترجیح دینے کے لیے (نیٹ ورک کے مسائل سے بچنے کے لیے)
dns.setDefaultResultOrder('ipv4first');

const app = express();

// CORS کنفیگریشن - تمام اوریجنز کو الاؤ کرنا تاکہ موبائل ایپ بلاک نہ ہو
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// عارضی OTP اسٹوریج
const otpStore = {};

// 1️⃣ او ٹی پی جنریٹ اور EmailJS کے ذریعے سینڈ کرنے کا API
app.post('/api/send-otp', async (req, res) => {
  const { email, name, otp } = req.body; 
  if (!email) return res.status(400).json({ error: "ای میل درج کرنا ضروری ہے" });

  const otpCode = otp || Math.floor(100000 + Math.random() * 900000).toString();
  const normalizedEmail = email.toLowerCase().trim();
  
  otpStore[normalizedEmail] = {
    otp: otpCode,
    expiresAt: Date.now() + 5 * 60 * 1000 // 5 منٹ کی ویلیڈٹی
  };

  // سرور لاگز میں او ٹی پی چیک کرنے کے لیے
  console.log(`\n---------------------------------`);
  console.log(`🔐 OTP for ${normalizedEmail} is: [ ${otpCode} ]`);
  console.log(`---------------------------------\n`);

  // EmailJS REST API کے لیے ڈیٹا پے لوڈ
  const emailJsData = {
    service_id: process.env.EMAILJS_SERVICE_ID,
    template_id: process.env.EMAILJS_TEMPLATE_ID,
    user_id: process.env.EMAILJS_PUBLIC_KEY, 
    template_params: {
      to_email: normalizedEmail,
      user_name: name || 'Nasirify User',
      otp_code: otpCode
    }
  };

  try {
    // Axios کا استعمال کرتے ہوئے EmailJS کو ڈیٹا بھیجنا
    const response = await axios.post('https://api.emailjs.com/api/v1.0/email/send', emailJsData, {
      headers: { 'Content-Type': 'application/json' }
    });

    if (response.status === 200) {
      console.log(`🚀 OTP sent successfully via EmailJS to ${normalizedEmail}`);
      return res.status(200).json({ success: true, message: "OTP sent via EmailJS!" });
    } else {
      throw new Error(`EmailJS responded with status: ${response.status}`);
    }

  } catch (error) {
    // اگر ای میل فیل بھی ہو جائے تو تفصیلی ایرر لاگ کریں
    console.error("❌ EmailJS Error Details:", error.response ? error.response.data : error.message);
    
    // کلاؤڈ پر لاگ میں دکھانے کے بعد بھی رسپانس کامیابی کا بھیجیں تاکہ ٹیسٹنگ نہ رکے
    console.log("⚠️ EmailJS failed! But continuing test via server logs OTP...");
    return res.status(200).json({ success: true, message: "OTP generated (Check server logs)!" });
  }
});

// 2️⃣ او ٹی پی ویریفائی کرنے کا API
app.post('/api/verify-otp', (req, res) => {
  const { email, otpEnteredByUser } = req.body;
  
  if (!email || !otpEnteredByUser) {
    return res.status(400).json({ success: false, message: "ای میل اور او ٹی پی دونوں ضروری ہیں" });
  }

  const userEmail = email.toLowerCase().trim();

  if (!otpStore[userEmail]) {
    return res.status(400).json({ success: false, message: "پہلے او ٹی پی کوڈ کی درخواست کریں" });
  }

  const { otp, expiresAt } = otpStore[userEmail];

  if (Date.now() > expiresAt) {
    delete otpStore[userEmail];
    return res.status(400).json({ success: false, message: "او ٹی پی کوڈ کی مدت ختم ہو چکی ہے" });
  }

  if (otpEnteredByUser.toString().trim() === otp.toString().trim()) {
    delete otpStore[userEmail]; 
    return res.status(200).json({ success: true, message: "Verified!" });
  } else {
    return res.status(400).json({ success: false, message: "غلط او ٹی پی کوڈ درج کیا گیا ہے" });
  }
});

// ✅ ریلوے (Railway) کے لیے '0.0.0.0' ہوسٹ پر بائنڈ کرنا لازمی ہے
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Security server running smoothly on port ${PORT}`);
});
