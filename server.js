const express = require('express');
const cors = require('cors');
const dns = require('dns');
const axios = require('axios');
const admin = require('firebase-admin');
require('dotenv').config();

// Firebase initialization
if (!admin.apps.length) {
  try {
    if (process.env.FIREBASE_PROJECT_ID) {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId: process.env.FIREBASE_PROJECT_ID,
          clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
          privateKey: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined
        })
      });
      console.log("✅ Firebase initialized with environment variables.");
    } else {
      admin.initializeApp({
        credential: admin.credential.applicationDefault()
      });
      console.log("✅ Firebase initialized with default credentials.");
    }
  } catch (error) {
    console.error("❌ Firebase Initialization Error:", error);
  }
}

// 🛡️ [UPDATE] Guard laga diya hai taake agar init fail ho to server crash na ho
const db = admin.apps.length ? admin.firestore() : null;

// IPv4 ko tarjeeh dene ke liye
dns.setDefaultResultOrder('ipv4first');

const app = express();

// CORS Configuration
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Temporary OTP Storage
const otpStore = {};

// 🔴 Admin Security Alert Function
async function sendAdminAlert(subject, details) {
  const adminEmailData = {
    service_id: process.env.EMAILJS_SERVICE_ID,
    template_id: process.env.EMAILJS_TEMPLATE_ID, 
    user_id: process.env.EMAILJS_PUBLIC_KEY, 
    template_params: {
      email: process.env.ADMIN_EMAIL || "admin@yourdomain.com",
      user_name: "Nasirify Security System",
      passcode: "SECURITY ALERT",
      time: new Date().toLocaleString(),
      message_details: `${subject}: ${details}` 
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

// 1️⃣ OTP Generate & Send API
app.post('/api/send-otp', async (req, res) => {
  const { email, name, deviceId } = req.body; 
  if (!email) return res.status(400).json({ error: "ای میل درج کرنا ضروری ہے" });

  const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
  const normalizedEmail = email.toLowerCase().trim();
  const currentDevice = deviceId || "unknown_device";
  
  otpStore[normalizedEmail] = {
    otp: otpCode,
    expiresAt: Date.now() + 5 * 60 * 1000,
    attempts: 0,
    deviceId: currentDevice
  };

  setTimeout(() => {
    if (otpStore[normalizedEmail] && otpStore[normalizedEmail].otp === otpCode) {
      delete otpStore[normalizedEmail];
      console.log(`🧹 [CLEANUP] Expired OTP memory cleared for ${normalizedEmail}`);
    }
  }, 5 * 60 * 1000);

  console.log(`\n---------------------------------`);
  console.log(`🔐 OTP for ${normalizedEmail} is: [ ${otpCode} ]`);
  console.log(`📱 Device ID: ${currentDevice}`);
  console.log(`---------------------------------\n`);

  const emailJsData = {
    service_id: process.env.EMAILJS_SERVICE_ID,
    template_id: process.env.EMAILJS_TEMPLATE_ID,
    user_id: process.env.EMAILJS_PUBLIC_KEY, 
    template_params: {
      email: normalizedEmail,        
      passcode: otpCode,            
      user_name: name || 'Nasirify User',
      time: "5 Minutes"             
    }
  };

  try {
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
    
    if (process.env.NODE_ENV === 'development') {
      console.log("⚠️ Dev Mode: Continuing test via server logs...");
      return res.status(200).json({ success: true, message: "OTP generated (Check server logs)!" });
    }
    
    return res.status(500).json({ success: false, message: "ای میل سروس میں خرابی ہے۔ براہ کرم دوبارہ کوشش کریں۔" });
  }
});

// 2️⃣ OTP Verification API
app.post('/api/verify-otp', async (req, res) => {
  const { email, otpEnteredByUser, deviceId } = req.body;
  
  if (!email || !otpEnteredByUser) {
    return res.status(400).json({ success: false, message: "ای میل اور او ٹی پی دونوں ضروری ہیں" });
  }

  const userEmail = email.toLowerCase().trim();
  const currentDevice = deviceId || "unknown_device";

  if (!otpStore[userEmail]) {
    return res.status(400).json({ success: false, message: "پہلے او ٹی پی کوڈ کی درخواست کریں یا کوڈ کی مدت ختم ہو چکی ہے" });
  }

  const session = otpStore[userEmail];

  if (Date.now() > session.expiresAt) {
    delete otpStore[userEmail];
    return res.status(400).json({ success: false, message: "او ٹی پی کوڈ کی مدت ختم ہو چکی ہے" });
  }

  if (session.attempts >= 3) {
    delete otpStore[userEmail];
    console.log(`🚨 [ALERT] Brute-force blocked for: ${userEmail}`);
    await sendAdminAlert("BRUTE FORCE WARNING", `User ${userEmail} tried to brute-force OTP multiple times.`);
    return res.status(429).json({ success: false, message: "بار بار غلط کوڈ درج کرنے کی وجہ سے آپ کا سیشن بلاک کر دیا گیا ہے۔" });
  }

  if (session.deviceId !== currentDevice) {
    console.log(`🚨 [ALERT] Device Mismatch detected for ${userEmail}!`);
    await sendAdminAlert("SUSPICIOUS LOGIN", `User ${userEmail} requested OTP from device [${session.deviceId}] but is verifying from device [${currentDevice}].`);
    return res.status(403).json({ 
      success: false, 
      message: "سیکیورٹی الرٹ: ڈیوائس تبدیل پائی گئی ہے۔ لاگ ان کی اجازت نہیں ہے۔" 
    });
  }

  if (otpEnteredByUser.toString().trim() === session.otp.toString().trim()) {
    delete otpStore[userEmail];
    console.log(`✅ User ${userEmail} verified on device ${currentDevice}`);
    return res.status(200).json({ success: true, message: "Verified!" });
  } else {
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

// 🛡️ Security Check Endpoint
app.post('/api/check-security', async (req, res) => {
  const { deviceId, email } = req.body;
  // [UPDATE] Check if db is initialized before usage
  if (!db) return res.status(500).json({ isAllowed: false, message: "DB Error" });
  
  try {
    const q = db.collection("users").where("deviceId", "==", deviceId).limit(1);
    const snapshot = await q.get();
    if (!snapshot.empty) return res.status(200).json({ isAllowed: false, message: "اس ڈیوائس پر اکاؤنٹ موجود ہے۔" });
    return res.status(200).json({ isAllowed: true });
  } catch (error) {
    return res.status(500).json({ isAllowed: false });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Security server running smoothly on port ${PORT}`);
});
