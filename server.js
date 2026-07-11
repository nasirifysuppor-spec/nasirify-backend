const express = require('express');
const cors = require('cors');
const dns = require('dns');
const axios = require('axios');
require('dotenv').config();

// IPv4 ko tarjih dene ke liye (Network routing issues se bachne ke liye)
dns.setDefaultResultOrder('ipv4first');

const app = express();

// CORS Configuration - Sabhi origins allowed hain taake mobile app block na ho
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
  if (!requestId || !clientVisitorId) return false;

  try {
    const secretKey = process.env.FINGERPRINT_SECRET_KEY; // Railway me save ki hui Secret Key (sk_...)
    
    // 🌍 CRITICAL REGION UPDATE: Aapke 'ap' region ke liye specific server endpoint
    const response = await axios.get(`https://ap.api.fpjs.io/events/${requestId}`, {
      headers: { 'Auth-API-Key': secretKey }
    });

    if (response.status === 200 && response.data.products?.identification?.data) {
      const serverVisitorId = response.data.products.identification.data.visitorId;
      
      // Mobile app ki visitorId aur Fingerprint server se aayi ID ka match hona zaroori hai
      if (serverVisitorId === clientVisitorId) {
        return true; 
      }
    }
    return false;
  } catch (error) {
    // Agar region ya key me masla hoga to exact detail console me dikhegi
    console.error("❌ Fingerprint Server Validation Error:", error.response ? error.response.data : error.message);
    return false; 
  }
}

// 1️⃣ OTP Generate aur EmailJS ke zariye send karne ka API
app.post('/api/send-otp', async (req, res) => {
  const { email, name, otp, requestId, visitorId } = req.body; 
  if (!email) return res.status(400).json({ error: "ای میل درج کرنا ضروری ہے" });

  // 🛡️ SECURITY STEP: Server-side fingerprint checking
  const isDeviceValid = await verifyFingerprintToken(requestId, visitorId);
  if (!isDeviceValid) {
    console.log(`🚨 Security Alert: Unauthorized device bypass attempt blocked for ${email}`);
    return res.status(403).json({ success: false, message: "سیکیورٹی الرٹ: غیر مجاز ڈیوائس یا بائی پاس کی کوشش بلاک کر دی گئی ہے۔" });
  }

  const otpCode = otp || Math.floor(100000 + Math.random() * 900000).toString();
  const normalizedEmail = email.toLowerCase().trim();
  
  otpStore[normalizedEmail] = {
    otp: otpCode,
    expiresAt: Date.now() + 5 * 60 * 1000 // 5 Minutes Validity
  };

  console.log(`\n---------------------------------`);
  console.log(`🔐 OTP for ${normalizedEmail} is: [ ${otpCode} ]`);
  console.log(`---------------------------------\n`);

  // EmailJS REST API payload
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
    
    // PRODUCTION FIX: Live app me fail hone par user ko error response bhejna zaroori hai
    if (process.env.NODE_ENV === 'production') {
      return res.status(500).json({ success: false, message: "ای میل سروس میں خرابی کی وجہ سے OTP نہیں بھیجا جا سکا۔" });
    }
    
    // Localhost / Dev mode test backup ke liye logs ka option default rakha hai
    return res.status(200).json({ success: true, message: "OTP generated (Check server logs)!" });
  }
});

// 2️⃣ OTP Verify karne ka API
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

// Railway (0.0.0.0 binding mandatory)
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Security server running smoothly on port ${PORT} [Region: AP]`);
});
