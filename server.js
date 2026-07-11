const express = require('express');
const cors = require('cors');
const dns = require('dns');
const axios = require('axios');
const admin = require('firebase-admin');
// 👑 Firestore ko naye standard tareeqay se import kiya
const { getFirestore } = require('firebase-admin/firestore'); 
require('dotenv').config();

// IPv4 کو ترجیح دینے کے لیے
dns.setDefaultResultOrder('ipv4first');

const app = express();

// 🟢 FIREBASE ADMIN SDK INITIALIZATION (SAFE FIX)
let db;
try {
  if (!admin.apps || admin.apps.length === 0) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined,
      })
    });
    console.log("🔥 Firebase Admin Initialized Successfully.");
  }
  db = getFirestore();
} catch (initError) {
  console.error("❌ Firebase Initialization Error:", initError.message);
}

// CORS Configuration
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Temporary OTP Storage
const otpStore = {};

// 🔒 FINGERPRINT VERIFICATION FUNCTION (Server-to-Server)
async function verifyFingerprintToken(requestId, clientVisitorId) {
  if (!requestId || !clientVisitorId || clientVisitorId === "unknown" || requestId === "unknown") {
    if (process.env.NODE_ENV !== 'production') return true;
    return false;
  }

  try {
    const secretKey = process.env.FINGERPRINT_SECRET_KEY; 
    const response = await axios.get(`https://ap.api.fpjs.io/events/${requestId}`, {
      headers: { 'Auth-API-Key': secretKey }
    });

    if (response.status === 200 && response.data.products?.identification?.data) {
      const serverVisitorId = response.data.products.identification.data.visitorId;
      if (serverVisitorId === clientVisitorId) {
        return true; 
      }
    }
    return false;
  } catch (error) {
    console.error("❌ Fingerprint Server Validation Error:", error.response ? error.response.data : error.message);
    return false; 
  }
}

// 🛰️ 1️⃣ لاگ ان گیٹ وے اور سیکیورٹی چیک API
app.post('/api/verify-login', async (req, res) => {
  const { email, uid, deviceId, platform, osVersion, isGoogleLogin, displayName, requestId } = req.body;
  const adminEmail = process.env.ADMIN_EMAIL;

  if (!email || !uid) {
    return res.status(400).json({ status: "error", message: "کریڈنشلز ادھورے ہیں۔" });
  }

  try {
    const normalizedEmail = email.toLowerCase().trim();
    const currentDevice = deviceId || "unknown";

    // 👑 ⭐ ADMIN VIP BYPASS (SAB SE OOPAR)
    // اگر ای میل ایڈمن کی ہے تو تمام سیکیورٹی فلٹرز اور او ٹی پی کو بائی پاس کر دیا جائے
    if (adminEmail && normalizedEmail === adminEmail.toLowerCase().trim()) {
      console.log(`👑 VIP Admin Access Granted Server-Side For: ${normalizedEmail}`);
      return res.status(200).json({ status: "admin_passed", role: "admin" });
    }

    if (!db) {
      return res.status(500).json({ status: "error", message: "ڈیٹا بیس کنکشن دستیاب نہیں ہے۔" });
    }

    // 🔥 سیکیورٹی چیک 1: ڈیوائس بلاک لسٹ ٹیسٹ (صرف عام صارفین کے لیے)
    if (currentDevice !== "unknown") {
      const blockSnap = await db.collection('blocked_devices').doc(currentDevice).get();
      if (blockSnap.exists()) {
        return res.status(403).json({ status: "blocked", message: "یہ ڈیوائس بلاک کر دی گئی ہے۔" });
      }
    }

    // 🔥 سیکیورٹی چیک 2: سرور سائیڈ فنگر پرنٹ ویریفکیشن (صرف عام صارفین کے لیے)
    const isDeviceGenuine = await verifyFingerprintToken(requestId, currentDevice);
    if (!isDeviceGenuine) {
      console.log(`🚨 Hack Alert: Fake fingerprint request blocked for ${normalizedEmail}`);
      return res.status(403).json({ status: "invalid_fingerprint", message: "سیکیورٹی الرٹ: ڈیوائس ٹوکن غیر مصدقہ ہے۔" });
    }

    // فائر اسٹور سے یوزر ڈیٹا نکالیں
    const userRef = db.collection('users').doc(uid);
    let userSnap = await userRef.get();

    // اگر گوگل سائن ان سے نیا یوزر ہے تو رجسٹر کریں
    if (!userSnap.exists() && isGoogleLogin) {
      const defaultData = {
        uid,
        name: displayName || "Google User",
        email: normalizedEmail,
        role: "buyer",
        deviceIds: currentDevice !== "unknown" ? [currentDevice] : [],
        isVerified: false,
        createdAt: new Date().toISOString()
      };
      await userRef.set(defaultData);
      return res.status(200).json({ status: "under_review" });
    }

    if (!userSnap.exists()) {
      return res.status(404).json({ status: "not_found", message: "یوزر ریکارڈ ڈیٹا بیس میں موجود نہیں ہے۔" });
    }

    const userData = userSnap.data();

    // 🔥 سیکیورٹی چیک 3: یوزر ویریفکیشن اسٹیٹس چیک
    if (userData.isVerified === false) {
      return res.status(200).json({ status: "under_review" });
    }

    // 🔥 سیکیورٹی چیک 4: ڈیوائس مس میچ پروٹیکشن
    if (userData.deviceIds && userData.deviceIds.length > 0 && currentDevice !== "unknown" && !userData.deviceIds.includes(currentDevice)) {
      
      await db.collection('suspicious_hack_attempts').add({
        email: normalizedEmail,
        deviceId: currentDevice,
        status: "mismatch",
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        platform: platform || "unknown",
        osVersion: osVersion || "unknown"
      });

      const attemptsSnap = await db.collection('login_attempts').where('deviceId', '==', currentDevice).get();
      const hacksSnap = await db.collection('suspicious_hack_attempts').where('deviceId', '==', currentDevice).get();
      const totalFailures = attemptsSnap.size + hacksSnap.size;

      if (totalFailures >= 4) {
        await db.collection('blocked_devices').doc(currentDevice).set({
          blockedEmail: normalizedEmail,
          reason: "Exceeded 4 unauthorized device mismatch attempts",
          blockedAt: admin.firestore.FieldValue.serverTimestamp(),
          deviceDetails: { platform, osVersion }
        });
        return res.status(403).json({ status: "blocked", message: "بار بار کوششوں کی وجہ سے ڈیوائس بلاک ہو گئی۔" });
      }

      return res.status(401).json({ status: "mismatch", message: "یہ اکاؤنٹ کسی دوسری ڈیوائس پر رجسٹرڈ ہے۔" });
    }

    // 🌟 تمام چیکس پاس: او ٹی پی جنریشن فلو (صرف عام صارفین کے لیے)
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    
    otpStore[normalizedEmail] = {
      otp: otpCode,
      expiresAt: Date.now() + 5 * 60 * 1000
    };

    console.log(`🔐 Generated OTP for ${normalizedEmail} -> [ ${otpCode} ]`);

    const emailJsData = {
      service_id: process.env.EMAILJS_SERVICE_ID,
      template_id: process.env.EMAILJS_TEMPLATE_ID,
      user_id: process.env.EMAILJS_PUBLIC_KEY, 
      template_params: {
        email: normalizedEmail,       
        passcode: otpCode,            
        user_name: userData.name || 'Nasirify User',
        time: "5 Minutes"             
      }
    };

    try {
      await axios.post('https://api.emailjs.com/api/v1.0/email/send', emailJsData, {
        headers: { 'Content-Type': 'application/json' }
      });
      console.log(`🚀 OTP successfully sent to ${normalizedEmail}`);
    } catch (emailError) {
      console.error("❌ EmailJS Delivery Error:", emailError.message);
      if (process.env.NODE_ENV === 'production') {
        return res.status(500).json({ status: "error", message: "ای میل سروس فیل ہونے کی وجہ سے او ٹی پی نہیں بھیجا جا سکا۔" });
      }
    }

    return res.status(200).json({ status: "otp_required", role: userData.role || 'buyer' });

  } catch (err) {
    console.error("🔥 Server Gate Failure:", err);
    return res.status(500).json({ status: "error", message: "انٹرنل سرور سیکیورٹی گیٹ ایرر۔" });
  }
});

// 2️⃣ OTP Verify کرنے اور لاگ ان ہسٹری بنانے کا API
app.post('/api/verify-otp', async (req, res) => {
  const { email, otpEnteredByUser, uid, deviceId, platform, osVersion } = req.body;
  
  if (!email || !otpEnteredByUser) {
    return res.status(400).json({ success: false, message: "ای میل اور او ٹی پی دونوں ضروری ہیں" });
  }

  const userEmail = email.toLowerCase().trim();
  const currentDevice = deviceId || "unknown";

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

    try {
      if (!db) throw new Error("Database not initialized");
      const historyRef = db.collection("login_history");
      const sessionDoc = await historyRef.add({
        uid: uid,
        email: userEmail,
        deviceId: currentDevice,
        loginAt: admin.firestore.FieldValue.serverTimestamp(),
        logoutAt: null,
        platform: platform || "unknown",
        osVersion: osVersion || "unknown"
      });

      await db.collection('login_attempts').add({
        email: userEmail,
        deviceId: currentDevice,
        status: "success",
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });

      return res.status(200).json({ 
        success: true, 
        message: "Verified!", 
        sessionId: sessionDoc.id 
      });

    } catch (dbError) {
      console.error("Error creating login session doc:", dbError);
      return res.status(200).json({ success: true, message: "Verified but history log failed." });
    }

  } else {
    if (currentDevice !== "unknown" && db) {
      await db.collection('login_attempts').add({
        email: userEmail,
        deviceId: currentDevice,
        status: "failed",
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
    }

    return res.status(400).json({ success: false, message: "غلط او ٹی پی کوڈ درج کیا گیا ہے" });
  }
});

// 🔄 3️⃣ لاگ آؤٹ اور سیشن ختم کرنے کا API
app.post('/api/logout', async (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).json({ success: false, message: "سیشن آئی ڈی ضروری ہے۔" });

  try {
    if (!db) throw new Error("Database not initialized");
    const sessionRef = db.collection("login_history").doc(sessionId);
    await sessionRef.update({
      logoutAt: admin.firestore.FieldValue.serverTimestamp()
    });
    return res.status(200).json({ success: true, message: "Logged out successfully from server!" });
  } catch (err) {
    console.error("❌ Server Logout Error:", err.message);
    return res.status(500).json({ success: false, message: "لاگ آؤٹ اپڈیٹ کرنے میں ناکامی۔" });
  }
});

// Railway Config
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Security server running smoothly on port ${PORT} [Region: AP]`);
});
