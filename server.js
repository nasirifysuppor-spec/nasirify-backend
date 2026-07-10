const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const dns = require('dns'); // نیٹ ورکنگ لیول ہینڈلنگ کے لیے
require('dotenv').config();

const app = express();

// CORS اور JSON مڈل ویئر
app.use(cors());
app.use(express.json());

// ریلوے ہیلتھ چیک روٹ (تاکہ سرور آن لائن رہے)
app.get('/', (req, res) => {
  res.status(200).send("Nasirify Backend is Live and Running!");
});

// جی میل ٹرانسپورٹر کا کلاؤڈ ہوسٹنگ کے لیے حتمی سیٹ اپ
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // پورٹ 587 کے لیے ہمیشہ false ہوتا ہے
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS // آپ کا 16 ہندسوں کا گوگل ایپ پاس ورڈ
  },
  tls: {
    rejectUnauthorized: false
  },
  // یہ جادوئی لائن ریلوے کے IPv6 ایرر (ENETUNREACH) کو بائی پاس کرے گی
  lookup: (hostname, options, callback) => {
    options.family = 4; // نوڈ جے ایس کو صرف IPv4 استعمال کرنے پر مجبور کریں
    dns.lookup(hostname, options, callback);
  }
});

// عارضی OTP اسٹوریج
const otpStore = {};

// 1️⃣ او ٹی پی جنریٹ اور سینڈ کرنے کا API
app.post('/api/send-otp', async (req, res) => {
  const { email, name, otp } = req.body;
  if (!email) return res.status(400).json({ error: "ای میل درج کرنا ضروری ہے" });

  const otpCode = otp || Math.floor(100000 + Math.random() * 900000).toString();
  const normalizedEmail = email.toLowerCase().trim();
  
  otpStore[normalizedEmail] = {
    otp: otpCode,
    expiresAt: Date.now() + 5 * 60 * 1000 
  };

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: normalizedEmail,
    subject: 'Nasirify Network - Login OTP',
    text: `السلام علیکم ${name || 'یوزر'}!\n\nNasirify نیٹ ورک پر لاگ ان کے لیے آپ کا ویریفیکیشن کوڈ یہ ہے: ${otpCode}\n\nیہ کوڈ 5 منٹ تک کام کرے گا۔`
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
    return res.status(400).json({ success: false, message: "او ٹی پی کوڈ کی مدت ختم ہو چکی ہے" });
  }

  if (otpEnteredByUser === otp) {
    delete otpStore[userEmail]; 
    return res.status(200).json({ success: true, message: "Verified!" });
  } else {
    return res.status(400).json({ success: false, message: "غلط او ٹی پی کوڈ درج کیا گیا ہے" });
  }
});

// ریلوے پورٹ بائنڈنگ
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
