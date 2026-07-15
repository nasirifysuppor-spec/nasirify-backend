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

// 🔄 پُرانے CORS کو اس سے تبدیل کریں:
app.use(cors({
  origin: true, // یہ ریکویسٹ بھیجنے والے اوریجن کو آٹو الاؤ کرے گا
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-app-secret'], // x-app-secret کو یہاں لازمی شامل کریں
  credentials: true
}));

app.use(express.json());

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

// 1️⃣ OTP Generate & Send API (Updated with 4 OTPs per Device/Day Limit)
app.post('/api/send-otp', async (req, res) => {
  const { email, name, deviceId } = req.body; 
  if (!email) return res.status(400).json({ error: "ای میل درج کرنا ضروری ہے" });

  const currentDevice = deviceId || "unknown_device";
  const normalizedEmail = email.toLowerCase().trim();

  // 🔄 [NEW FEATURE] Device Rate Limiting (Max 4 OTPs per 24 hours)
  if (db && currentDevice !== "unknown_device") {
    try {
      const deviceOtpRef = db.collection("device_otp_limits").doc(currentDevice);
      const deviceOtpSnap = await deviceOtpRef.get();
      const now = Date.now();
      const oneDayInMs = 24 * 60 * 60 * 1000;

      if (deviceOtpSnap.exists) {
        const data = deviceOtpSnap.data();
        
        // Agar aakhri OTP ko 24 ghante guzar chuke hain, to reset karein
        if (now - data.firstAttemptAt > oneDayInMs) {
          await deviceOtpRef.set({
            count: 1,
            firstAttemptAt: now,
            lastAttemptAt: now
          });
        } else {
          // Agar 24 ghante ke andar 4 se zyada requests hain
          if (data.count >= 4) {
            const timeLeft = Math.ceil((data.firstAttemptAt + oneDayInMs - now) / (60 * 60 * 1000));
            return res.status(429).json({ 
              success: false, 
              message: `سیکیورٹی الرٹ: آپ اس ڈیوائس پر 24 گھنٹوں میں صرف 4 بار او ٹی پی منگوا سکتے ہیں۔ براہ کرم ${timeLeft} گھنٹے بعد کوشش کریں۔` 
            });
          }
          
          // Count barhaein
          await deviceOtpRef.update({
            count: data.count + 1,
            lastAttemptAt: now
          });
        }
      } else {
        // Pehli entry create karein
        await deviceOtpRef.set({
          count: 1,
          firstAttemptAt: now,
          lastAttemptAt: now
        });
      }
    } catch (dbError) {
      console.error("❌ Device OTP Limit DB Error:", dbError.message);
      // DB fail hone par safe-side ke liye check bypass kar rahe hain taaki genuine users block na hon
    }
  }

  // OTP Generation Logic
// OTP Generation Logic
  const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
  
  // 🔄 OTP Store میں 20 سیکنڈ کا کول ڈاؤن ہینڈل کرنے کے لیے timestamp شامل کر سکتے ہیں 
  // مگر ہم نے DB میں پہلے ہی lastAttemptAt اپ ڈیٹ کر دیا ہے۔
  otpStore[normalizedEmail] = {
    otp: otpCode,
    expiresAt: Date.now() + 5 * 60 * 1000,
    attempts: 0,
    deviceId: currentDevice
  };

  // 5 منٹ بعد میموری کلین اپ
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
      return res.status(200).json({ 
        success: true, 
        message: "OTP کامیابی سے بھیج دیا گیا ہے!" 
      });
    } else {
      throw new Error(`EmailJS status: ${response.status}`);
    }

  } catch (error) {
    // اگر ایرر آئے تو ہم OTP اسٹور سے ہٹا دیتے ہیں تاکہ دوبارہ فوری کوشش ممکن ہو سکے
    delete otpStore[normalizedEmail];
    
    console.error("❌ EmailJS Error Details:", error.response ? error.response.data : error.message);
    
    if (process.env.NODE_ENV === 'development') {
      console.log("⚠️ Dev Mode: Continuing test via server logs...");
      return res.status(200).json({ success: true, message: "OTP generated (Check server logs)!" });
    }
    
    return res.status(500).json({ 
      success: false, 
      message: "ای میل سروس میں خرابی ہے۔ براہ کرم کچھ سیکنڈز بعد دوبارہ کوشش کریں۔" 
    });
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
// 🛡️ Security Check Endpoint (Updated for Role-based Multi-Account Logic)
app.post('/api/check-security', async (req, res) => {
  const { deviceId, email, role } = req.body; // Frontend se 'role' (buyer/seller) bhejna zaroori hai
  if (!db) return res.status(500).json({ isAllowed: false, message: "DB Error" });
  
  try {
    const normalizedEmail = email.toLowerCase().trim();

    // 1. Check: Kya device pehle se BANNED hai?
    const attemptRef = db.collection("signup_attempts").doc(deviceId);
    const attemptSnap = await attemptRef.get();
    
    if (attemptSnap.exists && attemptSnap.data().isBanned) {
      return res.status(403).json({ isAllowed: false, message: "سیکیورٹی الرٹ: اس ڈیوائس پر پابندی عائد ہے۔" });
    }

    // 2. Device par mojood accounts check karein
    const deviceSnapshot = await db.collection("users").where("deviceId", "==", deviceId).get();
    
    let existingRoles = [];
    deviceSnapshot.forEach(doc => {
      existingRoles.push(doc.data().role);
    });

    // 3. Logic: Check if registration is allowed
    // Agar device par pehle se 'buyer' AND 'seller' dono hain -> Block
    if (existingRoles.includes('buyer') && existingRoles.includes('seller')) {
      return res.status(403).json({ 
        isAllowed: false, 
        message: "اس ڈیوائس پر پہلے سے ہی ایک Buyer اور ایک Seller اکاؤنٹ موجود ہے۔ مزید اکاؤنٹ بنانا ممکن نہیں۔" 
      });
    }

    // Agar user wahi role dobara banane ki koshish kar raha hai jo pehle se hai
    if (existingRoles.includes(role)) {
      return res.status(403).json({ 
        isAllowed: false, 
        message: `اس ڈیوائس پر پہلے سے ایک ${role} اکاؤنٹ موجود ہے۔` 
      });
    }

    // 4. Duplicate Email Check
    const emailSnapshot = await db.collection("users").where("email", "==", normalizedEmail).limit(1).get();
    if (!emailSnapshot.empty) {
      return res.status(403).json({ isAllowed: false, message: "یہ ای میل پہلے سے رجسٹرڈ ہے۔" });
    }

    // 5. Banned list check (Static)
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
