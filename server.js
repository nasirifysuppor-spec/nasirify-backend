const express = require('express');
const cors = require('cors');
const dns = require('dns');
const axios = require('axios');
const admin = require('firebase-admin');
const helmet = require('helmet'); // Security headers
const rateLimit = require('express-rate-limit'); // Rate limiting
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

const db = admin.apps.length ? admin.firestore() : null;

dns.setDefaultResultOrder('ipv4first');

const app = express();

// 🛡️ [SECURITY MIDDLEWARES]
app.use(helmet()); // Basic security headers
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { success: false, message: "Too many requests, please try again later." }
});
app.use(limiter);

// CORS Configuration
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Server.js mein yahan add karein
app.use((req, res, next) => {
  const secretKey = req.headers['x-app-secret'];
  
  if (!secretKey || secretKey !== process.env.MY_SECRET_APP_KEY) {
    console.warn(`❌ Unauthorized access attempt!`);
    return res.status(401).json({ success: false, message: "Unauthorized access!" });
  }
  next(); 
});

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

// 2️⃣ OTP Verification API (Database Integrated)
app.post('/api/verify-otp', async (req, res) => {
  const { email, otpEnteredByUser, deviceId } = req.body;
  
  if (!email || !otpEnteredByUser) {
    return res.status(400).json({ success: false, message: "ای میل اور او ٹی پی دونوں ضروری ہیں" });
  }

  const userEmail = email.toLowerCase().trim();
  const currentDevice = deviceId || "unknown_device";

  try {
    // 1. Check: Kya user DB mein permanent block hai?
    const userRef = db.collection("users").where("email", "==", userEmail);
    const userSnap = await userRef.get();
    
    if (!userSnap.empty) {
      const userData = userSnap.docs[0].data();
      if (userData.blockedUntil && Date.now() < userData.blockedUntil) {
        return res.status(429).json({ 
          success: false, 
          message: "بار بار غلط کوششوں کی وجہ سے آپ کا اکاؤنٹ 24 گھنٹے کے لیے بلاک ہے۔" 
        });
      }
    }

    // 2. Memory check
    if (!otpStore[userEmail]) {
      return res.status(400).json({ success: false, message: "کوڈ کی مدت ختم ہو چکی ہے، دوبارہ درخواست کریں۔" });
    }

    const session = otpStore[userEmail];

    // Expiry Check
    if (Date.now() > session.expiresAt) {
      delete otpStore[userEmail];
      return res.status(400).json({ success: false, message: "او ٹی پی کوڈ کی مدت ختم ہو چکی ہے" });
    }

    // Device Mismatch
    if (session.deviceId !== currentDevice) {
      await sendAdminAlert("SUSPICIOUS LOGIN", `User ${userEmail} device mismatch. Attempting from ${currentDevice}.`);
      return res.status(403).json({ success: false, message: "سیکیورٹی الرٹ: ڈیوائس تبدیل پائی گئی ہے۔" });
    }

    // 3. Logic: OTP Check
    if (otpEnteredByUser.toString().trim() === session.otp.toString().trim()) {
      delete otpStore[userEmail];
      // Success: Reset block if any
      if (!userSnap.empty) {
        await userSnap.docs[0].ref.update({ blockedUntil: null });
      }
      return res.status(200).json({ success: true, message: "Verified!" });
    } else {
      session.attempts += 1;
      
      // 4. Block Logic: 4 attempts full?
      if (session.attempts >= 4) {
        if (!userSnap.empty) {
          const oneDay = 24 * 60 * 60 * 1000;
          await userSnap.docs[0].ref.update({ blockedUntil: Date.now() + oneDay });
        }
        delete otpStore[userEmail];
        await sendAdminAlert("BRUTE FORCE WARNING", `User ${userEmail} blocked for 24 hours.`);
        return res.status(429).json({ success: false, message: "4 غلط کوششیں۔ اکاؤنٹ 24 گھنٹے کے لیے بلاک کر دیا گیا ہے۔" });
      }

      const remaining = 4 - session.attempts;
      return res.status(400).json({ 
        success: false, 
        message: `غلط او ٹی پی کوڈ۔ باقی کوششیں: ${remaining}`,
        remainingAttempts: remaining
      });
    }
  } catch (error) {
    console.error("Verification Error:", error);
    return res.status(500).json({ success: false, message: "سرور ایرر" });
  }
});

// 🛡️ Security Check Endpoint (Updated for Auto-Blocking)
app.post('/api/check-security', async (req, res) => {
  const { deviceId, email } = req.body;
  if (!db) return res.status(500).json({ isAllowed: false, message: "DB Error" });
  
  try {
    const normalizedEmail = email.toLowerCase().trim();

    // 1. Check: Kya device pehle se BANNED hai?
    const attemptRef = db.collection("signup_attempts").doc(deviceId);
    const attemptSnap = await attemptRef.get();
    
    if (attemptSnap.exists && attemptSnap.data().isBanned) {
      return res.status(403).json({ isAllowed: false, message: "سیکیورٹی الرٹ: اس ڈیوائس پر پابندی عائد ہے۔" });
    }

    // 2. Duplicate Check (Device or Email)
    const deviceSnapshot = await db.collection("users").where("deviceId", "==", deviceId).limit(1).get();
    const emailSnapshot = await db.collection("users").where("email", "==", normalizedEmail).limit(1).get();

    if (!deviceSnapshot.empty || !emailSnapshot.empty) {
      // Asal account ki maloomat nikalna
      const existingAccount = !deviceSnapshot.empty ? deviceSnapshot.docs[0].data() : emailSnapshot.docs[0].data();
      
      // Attempt count increment
      const currentCount = attemptSnap.exists ? (attemptSnap.data().count || 0) : 0;
      const newCount = currentCount + 1;

      // 3. Attempt record save karna
      await attemptRef.set({
        count: newCount,
        isBanned: newCount >= 3, // 3 koshishon par auto-block
        lastAttempt: new Date().toISOString(),
        attemptedEmail: normalizedEmail, // Jo user ne abhi daali
        existingAccountEmail: existingAccount.email, // Asal registered email
        existingAccountName: existingAccount.name
      }, { merge: true });

      if (newCount >= 3) {
        return res.status(403).json({ 
          isAllowed: false, 
          message: "بار بار ملٹیپل اکاؤنٹ بنانے کی کوشش پر آپ کو مستقل بلاک کر دیا گیا ہے۔" 
        });
      }

      return res.status(200).json({ 
        isAllowed: false, 
        message: `یہ ڈیوائس یا ای میل پہلے سے رجسٹرڈ ہے۔ کوششیں باقی: ${3 - newCount}` 
      });
    }

    // 4. Banned list check (Static)
    const bannedRef = await db.collection("banned_devices").doc(deviceId).get();
    if (bannedRef.exists) return res.status(403).json({ isAllowed: false, message: "ڈیوائس بلاک ہے۔" });

    return res.status(200).json({ isAllowed: true });
  } catch (error) {
    console.error("Security Check Error:", error);
    return res.status(500).json({ isAllowed: false, message: "سرور ایرر" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Security server running smoothly on port ${PORT}`);
});
