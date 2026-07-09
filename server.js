const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();

// CORS کو اس طرح سیٹ کریں تاکہ موبائل ایپ کنیکٹ ہو سکے
app.use(cors());
app.use(express.json());

// جی میل ٹرانسپورٹر کا سیٹ اپ
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// عارضی OTP اسٹوریج
const otpStore = {};

// 1️⃣ او ٹی پی جنریٹ اور سینڈ کرنے کا API
app.post('/api/send-otp', async (req, res) => {
  const { email, name } = req.body;
  if (!email) return res.status(400).json({ error: "ای میل درج کرنا ضروری ہے" });

  const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
  
  otpStore[email.toLowerCase().trim()] = {
    otp: otpCode,
    expiresAt: Date.now() + 5 * 60 * 1000 // 5 منٹ کی ویلیڈٹی
  };

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Nasirify Network - Registration OTP',
    text: `السلام علیکم ${name || 'یوزر'}!\n\nNasirify نیٹ ورک پر رجسٹریشن کے لیے آپ کا ویریفیکیشن کوڈ یہ ہے: ${otpCode}\n\nیہ کوڈ سیکیورٹی وجوہات کی بنا پر صرف 5 منٹ تک کام کرے گا۔`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`OTP sent successfully to ${email}`);
    res.status(200).json({ success: true, message: "OTP sent securely!" });
  } catch (error) {
    console.error("Email Error:", error);
    res.status(500).json({ error: "ای میل بھیجنے میں سرور پر مسئلہ ہوا ہے۔" });
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

// سرور پورٹ رن کرنا
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Security server is fully loaded on port ${PORT}`));