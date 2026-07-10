const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();

// CORS اور JSON مڈل ویئر
app.use(cors());
app.use(express.json());

// ریلوے ہیلتھ چیک روٹ
app.get('/', (req, res) => {
  res.status(200).send("Nasirify Backend is Live and Running!");
});

// جی میل ٹرانسپورٹر (براہ راست گوگل کے IPv4 ایڈریس کا استعمال)
const transporter = nodemailer.createTransport({
  host: '74.125.142.108', // یہ 'smtp.gmail.com' کا آفیشل IPv4 ایڈریس ہے (یہ IPv6 کو بائی پاس کرے گا)
  port: 465, // پورٹ 465 کا استعمال کریں
  secure: true, // پورٹ 465 کے لیے true ہونا ضروری ہے
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS // ریلوے انوائرمنٹ ویریبلز والا App Password
  },
  tls: {
    servername: 'smtp.gmail.com', // ایس ایس ایل سرٹیفکیٹ کی تصدیق کے لیے یہ لائن لازمی ہے
    rejectUnauthorized: false
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
