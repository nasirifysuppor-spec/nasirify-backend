const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();

// CORS سیٹ اپ تاکہ موبائل ایپ بغیر کسی مسئلے کے ڈیٹا بھیج اور وصول کر سکے
app.use(cors());
app.use(express.json());

// جی میل ٹرانسپورٹر کا سیٹ اپ (پورٹ 587 - ریلوے اور کلاؤڈ ہوسٹنگ کے لیے بالکل محفوظ)
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // پورٹ 587 کے لیے ہمیشہ false رکھنا ضروری ہے
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS // ریلوے Variables میں آپ کا 16 ہندسوں کا گوگل App Password ہونا چاہیے
  },
  tls: {
    rejectUnauthorized: false // کلاؤڈ ہوسٹنگ پر کنکشن بلاک یا فیل ہونے سے روکتا ہے
  }
});

// عارضی OTP اسٹوریج
const otpStore = {};

// 1️⃣ او ٹی پی جنریٹ اور سینڈ کرنے کا API
app.post('/api/send-otp', async (req, res) => {
  const { email, name, otp } = req.body;
  if (!email) return res.status(400).json({ error: "ای میل درج کرنا ضروری ہے" });

  // اگر موبائل ایپ نے خود او ٹی پی بھیجا ہے تو وہ استعمال کریں، ورنہ نیا جنریٹ کریں
  const otpCode = otp || Math.floor(100000 + Math.random() * 900000).toString();
  const normalizedEmail = email.toLowerCase().trim();
  
  otpStore[normalizedEmail] = {
    otp: otpCode,
    expiresAt: Date.now() + 5 * 60 * 1000 // 5 منٹ کی ویلیڈٹی
  };

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: normalizedEmail,
    subject: 'Nasirify Network - Login OTP',
    text: `السلام علیکم ${name || 'یوزر'}!\n\nNasirify نیٹ ورک پر لاگ ان / رجسٹریشن کے لیے آپ کا ویریفیکیشن کوڈ یہ ہے: ${otpCode}\n\nیہ کوڈ سیکیورٹی وجوہات کی بنا پر صرف 5 منٹ تک کام کرے گا۔`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`🚀 OTP sent successfully to ${normalizedEmail}`);
    res.status(200).json({ success: true, message: "OTP sent securely!" });
  } catch (error) {
    console.error("Email Error:", error);
    res.status(500).json({ error: "ای میل بھیجنے میں سرور پر مسئلہ ہوا ہے۔", details: error.message });
  }
});

// 2️⃣ او ٹی پی ویریفائی کرنے کا API
app.post('/api/verify-otp', (req, res) => {
  const { email, otpEnteredByUser } = req.body;
  const userEmail = email.toLowerCase().trim();

  if (!otpStore[userEmail]) {
    return res.status(400).json({ success: false, message: "پہلے او ٹی پی کوڈ کی درخواست کریں" });
  }

  const { otp, expiresAt } = otpStore[userEmail];

  if (Date.now() > expiresAt) {
    delete otpStore[userEmail];
    return res.status(400).json({ success: false, message: "او ٹی پی کوڈ کی مدت ختم ہو چکی ہے، دوبارہ کوڈ بھیجیں" });
  }

  if (otpEnteredByUser === otp) {
    delete otpStore[userEmail]; // میچ ہونے پر ڈیلیٹ کر دیں
    return res.status(200).json({ success: true, message: "Verified!" });
  } else {
    return res.status(400).json({ success: false, message: "غلط او ٹی پی کوڈ درج کیا گیا ہے" });
  }
});

// سرور پورٹ رن کرنا - '0.0.0.0' لازمی ہے تاکہ ریلوے کا ہیلتھ چیک سسٹم کامیابی سے کنیکٹ رہے
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Security server is fully loaded on port ${PORT}`);
});
