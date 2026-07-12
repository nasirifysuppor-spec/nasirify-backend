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

// عارضی OTP اسٹوریج (سیکیورٹی ڈیٹا کے ساتھ)
const otpStore = {};

// 🔴 ایڈمن کو سیکیورٹی الرٹ ای میل بھیجنے کا فنکشن
async function sendAdminAlert(subject, details) {
  const adminEmailData = {
    service_id: process.env.EMAILJS_SERVICE_ID,
    template_id: process.env.EMAILJS_TEMPLATE_ID, // آپ اپنا ایڈمن والا ٹیمپلیٹ آئی ڈی بھی یہاں ڈال سکتے ہیں
    user_id: process.env.EMAILJS_PUBLIC_KEY, 
    template_params: {
      email: process.env.ADMIN_EMAIL || "admin@yourdomain.com", // ایڈمن کی ای میل (.env سے آئے گی)
      user_name: "Nasirify Security System",
      passcode: "SECURITY ALERT",
      time: new Date().toLocaleString(),
      message_details: `${subject}: ${details}` // ٹیمپلیٹ میں اگر کوئی کسٹم میسج فیلڈ ہو تو
    }
  };

  try {
    await axios.post('https://api.emailjs.com/api/v1.0/email/send', adminEmailData, {
      headers: { 'Content-Type': 'application/json' }
    });
    console.log("🚨 [SECURITY] Admin Alert email sent successfully.");
  } catch (err) {
    console.error("❌ Failed to send security alert to admin:", err.message);
  }
}

// 1️⃣ او ٹی پی جنریٹ اور EmailJS کے ذریعے سینڈ کرنے کا API
app.post('/api/send-otp', async (req, res) => {
  const { email, name, otp, deviceId } = req.body; 
  if (!email) return res.status(400).json({ error: "ای میل درج کرنا ضروری ہے" });

  const otpCode = otp || Math.floor(100000 + Math.random() * 900000).toString();
  const normalizedEmail = email.toLowerCase().trim();
  const currentDevice = deviceId || "unknown_device";
  
  // اب یہاں ہم attempts (کوششیں) اور deviceId بھی سیو کر رہے ہیں
  otpStore[normalizedEmail] = {
    otp: otpCode,
    expiresAt: Date.now() + 5 * 60 * 1000, // 5 منٹ کی ویلیڈٹی
    attempts: 0,
    deviceId: currentDevice
  };

  // سرور لاگز میں او ٹی پی چیک کرنے کے لیے
  console.log(`\n---------------------------------`);
  console.log(`🔐 OTP for ${normalizedEmail} is: [ ${otpCode} ]`);
  console.log(`📱 Device ID: ${currentDevice}`);
  console.log(`---------------------------------\n`);

  // ✅ EmailJS REST API ڈیٹا پے لوڈ
  const emailJsData = {
    service_id: process.env.EMAILJS_SERVICE_ID,
    template_id: process.env.EMAILJS_TEMPLATE_ID,
    user_id: process.env.EMAILJS_PUBLIC_KEY, 
    template_params: {
      email: normalizedEmail,       // ٹیمپلیٹ کا {{email}}
      passcode: otpCode,            // ٹیمپلیٹ کا {{passcode}}
      user_name: name || 'Nasirify User',
      time: "5 Minutes"             // ٹیمپلیٹ کا {{time}}
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
    console.error("❌ EmailJS Error Details:", error.response ? error.response.data : error.message);
    
    // سیکیورٹی فکس: اگر ای میل فیل ہو جائے تو رئیل پروڈکشن میں رسپانس فیل ہونا چاہیے تاکہ ہیکر فائدہ نہ اٹھائے
    if (process.env.NODE_ENV === 'development') {
      console.log("⚠️ Dev Mode: Continuing test via server logs...");
      return res.status(200).json({ success: true, message: "OTP generated (Check server logs)!" });
    }
    
    return res.status(500).json({ success: false, message: "ای میل سروس میں خرابی ہے۔ براہ کرم دوبارہ کوشش کریں۔" });
  }
});

// 2️⃣ او ٹی پی ویریفائی کرنے کا API (سیکیور ورژن)
app.post('/api/verify-otp', async (req, res) => {
  const { email, otpEnteredByUser, deviceId } = req.body;
  
  if (!email || !otpEnteredByUser) {
    return res.status(400).json({ success: false, message: "ای میل اور او ٹی پی دونوں ضروری ہیں" });
  }

  const userEmail = email.toLowerCase().trim();
  const currentDevice = deviceId || "unknown_device";

  if (!otpStore[userEmail]) {
    return res.status(400).json({ success: false, message: "پہلے او ٹی پی کوڈ کی درخواست کریں" });
  }

  const session = otpStore[userEmail];

  // 1. چیک کریں کہ کہیں او ٹی پی ایکسپائر تو نہیں ہو گیا
  if (Date.now() > session.expiresAt) {
    delete otpStore[userEmail];
    return res.status(400).json({ success: false, message: "او ٹی پی کوڈ کی مدت ختم ہو چکی ہے" });
  }

  // 2. بروٹ فورس پروٹیکشن (زیادہ سے زیادہ 3 کوششیں)
  if (session.attempts >= 3) {
    delete otpStore[userEmail];
    console.log(`🚨 [ALERT] Brute-force blocked for: ${userEmail}`);
    
    // ایڈمن کو سیکیورٹی الرٹ بھیجیں
    await sendAdminAlert("BRUTE FORCE WARNING", `User ${userEmail} tried to brute-force OTP multiple times.`);
    
    return res.status(429).json({ success: false, message: "بار بار غلط کوڈ درج کرنے کی وجہ سے آپ کا سیشن بلاک کر دیا گیا ہے۔" });
  }

  // 3. ڈیوائس آئی ڈی لاکنگ چیک (اگر او ٹی پی مانگنے والی ڈیوائس اور ویریفائی کرنے والی مختلف ہوں)
  if (session.deviceId !== currentDevice) {
    console.log(`🚨 [ALERT] Device Mismatch detected for ${userEmail}!`);
    
    // ایڈمن کو مشکوک ڈیوائس کا الرٹ بھیجیں
    await sendAdminAlert("SUSPICIOUS LOGIN", `User ${userEmail} requested OTP from device [${session.deviceId}] but is verifying from device [${currentDevice}].`);
  }

  // 4. او ٹی پی میچنگ لاجک
  if (otpEnteredByUser.toString().trim() === session.otp.toString().trim()) {
    delete otpStore[userEmail]; // ری پلے اٹیک سے بچنے کے لیے او ٹی پی فوراً ختم
    console.log(`✅ User ${userEmail} verified on device ${currentDevice}`);
    return res.status(200).json({ success: true, message: "Verified!" });
  } else {
    // غلط کوشش پر کاؤنٹر بڑھائیں
    session.attempts += 1;
    const remaining = 3 - session.attempts;
    
    console.log(`⚠️ Invalid OTP for ${userEmail}. Remaining attempts: ${remaining}`);
    
    return res.status(400).json({ 
      success: false, 
      message: `غلط او ٹی پی کوڈ۔ باقی کوششیں: ${remaining}`,
      remainingAttempts: remaining
    });
  }
});

// ریلوے (Railway) کے لیے '0.0.0.0' ہوسٹ پر بائنڈ کرنا لازمی ہے
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Security server running smoothly on port ${PORT}`);
});
