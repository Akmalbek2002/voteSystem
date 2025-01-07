const express = require('express');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const { Client } = require('pg');
const path = require('path');
const bcrypt = require('bcrypt');
const fs = require('fs');
const morgan = require('morgan');
const app = express();
const session = require('express-session');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const cors = require('cors');
const { Pool } = require('pg');
app.use(cors()); // CORSni yoqish
// Sessiya uchun sozlamalar

const port = 3000;

// Tub sonni tekshirish funksiyasi (Miller-Rabin testi)
function isProbablyPrime(n, iterations = 5) {
    if (n < 2n) return false;
    if (n === 2n || n === 3n) return true;
    if (n % 2n === 0n) return false;

    let s = 0n;
    let d = n - 1n;
    while (d % 2n === 0n) {
        d /= 2n;
        s += 1n;
    }

    for (let i = 0; i < iterations; i++) {
        const a = generateRandomBigInt(2n, n - 1n); // Katta tasodifiy a tanlash
        let x = modPow(a, d, n);
        if (x === 1n || x === n - 1n) continue;

        let composite = true;
        for (let r = 0n; r < s - 1n; r++) {
            x = modPow(x, 2n, n);
            if (x === n - 1n) {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }

    return true;
}

// Modular eksponentatsiyani hisoblash
function modPow(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2n === 1n) {
            result = (result * base) % mod;
        }
        exp = exp / 2n;
        base = (base * base) % mod;
    }
    return result;
}

// Tasodifiy katta son yaratish
function generateRandomBigInt(min, max) {
    const range = max - min + 1n;
    const byteLength = Math.ceil(range.toString(2).length / 8);
    let randomBigInt;
    do {
        const randomBytes = crypto.randomBytes(byteLength);
        randomBigInt = BigInt('0x' + randomBytes.toString('hex'));
    } while (randomBigInt >= range);
    return randomBigInt + min;
}

// Tasodifiy katta tub son yaratish funksiyasi
function generatePrime(bits) {
    let prime;
    do {
        prime = generateRandomBigInt(2n ** BigInt(bits - 1), 2n ** BigInt(bits) - 1n);
    } while (!isProbablyPrime(prime));
    return prime;
}

// gcd funksiyasi (Eng katta umumiy bo'luvchi)
function gcd(a, b) {
    while (b !== 0n) {
        [a, b] = [b, a % b];
    }
    return a;
}

// Modular inversni hisoblash funksiyasi (Extended Euclidean Algorithm)
function modularInverse(a, m) {
    let m0 = m;
    let y = 0n, x = 1n;

    while (a > 1n) {
        const q = a / m;
        [m, a] = [a % m, m];
        [y, x] = [x - q * y, y];
    }

    if (x < 0n) x += m0;
    return x;
}

// RSA kalitlarini generatsiya qilish
function generateRSAKeys(bits = 2048) {
    const P = generatePrime(bits / 2);
    const Q = generatePrime(bits / 2);
    const N = P * Q;
    const phi = (P - 1n) * (Q - 1n);

    // e ni tanlash
    let e = 65537n; // Standart qiymat
    if (gcd(e, phi) !== 1n) {
        throw new Error('e va phi(N) o‘zaro tub emas!');
    }

    // d ni hisoblash
    const d = modularInverse(e, phi);

    return {
        publicKey: { e, N },
        privateKey: { d, N },
    };
}

// Kalitlarni generatsiya qilish
const keys = generateRSAKeys(2048);
// Ochiq kalitni yuborish API
app.get('/get-public-key', (req, res) => {
    const { e, N } = keys.publicKey;

    // PEM formatni qo'lda generatsiya qilish
    const publicKeyPEM = `-----BEGIN RSA PUBLIC KEY-----\n` +
        Buffer.from(`${e.toString(16)}|${N.toString(16)}`, 'utf-8').toString('base64') +
        `\n-----END RSA PUBLIC KEY-----`;

    res.send({
        publicKey: publicKeyPEM,
    });
});



// RSA kalitlarni yaratish
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

let captchaStore = {}; // Vaqtinchalik CAPTCHA saqlash

// CAPTCHA-ni tekshirish API
app.post('/verify-captcha', (req, res) => {
    const { captcha, sessionId } = req.body;

    if (captcha === captchaStore[sessionId]) {
        delete captchaStore[sessionId];
        return res.status(200).send({ success: true });
    }

    res.status(400).send({ success: false, message: 'CAPTCHA noto‘g‘ri' });
});


// PostgreSQL bazasi ulanishi
const client = new Client({
  user: 'postgres',  // PostgreSQL foydalanuvchi nomi
  host: 'localhost',
  database: 'ovozDb',
  password: 'akmal625',  // PostgreSQL parol
  port: 5432,
});
client.connect();


// Wifi orqali ulanish uchun baza
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'ovozDb',
    password: 'akmal625',
    port: 5432,
});
pool.connect();

// Body parser
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false })); // Forma ma'lumotlarini qabul qilish uchun
app.use(express.json()); // JSON formatidagi kiruvchi ma'lumotlarni qo'llab-quvvatlash

// /register marshrutini qo‘shish
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Foydalanuvchi va ovozlar bo'yicha o'zgaruvchilar
let userEmail = '';
let selectedCandidate = '';
let verificationCode = '';

// Logs papkasini yaratish
if (!fs.existsSync('./logs')) {
    fs.mkdirSync('./logs');
}

// Loglar uchun streamlarni sozlash
const combinedLogStream = fs.createWriteStream(path.join(__dirname, 'logs', 'combined.log'), { flags: 'a' });
const errorLogStream = fs.createWriteStream(path.join(__dirname, 'logs', 'error.log'), { flags: 'a' });

// Morgan middleware
app.use(morgan('combined', { stream: combinedLogStream })); // Har bir so‘rovni combined.log ga yozish
app.use(morgan('common', {
    skip: (req, res) => res.statusCode < 400, // Faqat 4xx va 5xx xatolarini yozish
    stream: errorLogStream
}));

// Xatolarni ushlash middleware
app.use((err, req, res, next) => {
    const errorDetails = `${new Date().toISOString()} - ${req.method} ${req.url} - ${err.stack}\n`;
    errorLogStream.write(errorDetails); // error.log ga yozish
    console.error(errorDetails); // Konsolga chiqarish
    res.status(500).send('Serverda xatolik yuz berdi.');
});

// Route to serve the admin login page
app.get('/admin-login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
});



// Adminni tekshirish va saqlash
const checkAndInsertAdmin = async () => {
    try {
        // Tekshirib ko'rish, admin allaqachon mavjudmi
        const result = await client.query('SELECT * FROM admin WHERE email = $1', ['admin@domain.com']);
        
        // Agar admin mavjud bo'lmasa, uni saqlash
        if (result.rows.length === 0) {
            const password = 'adminPassword'; // Admin paroli
            await client.query(
                'INSERT INTO admin (first_name, last_name, email, password) VALUES ($1, $2, $3, $4)',
                ['Admin', 'User', 'admin@domain.com', password]
            );
            console.log('Admin muvaffaqiyatli saqlandi.');
        } else {
            
        }
    } catch (err) {
        console.error('Adminni tekshirishda yoki saqlashda xatolik:', err);
    }
};

// Email yuborish funksiyasi
const sendVerificationEmail = (email) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'axrorovakmal4@gmail.com',
            pass: 'ydpjyxvlxmlbobki'
        }
    });

    verificationCode = crypto.randomInt(100000, 999999).toString();  // Tasdiqlash kodi

    const mailOptions = {
        from: 'axrorovakmal4@gmail.com',
        to: email,
        subject: 'Ovoz berish uchun tasdiqlash kodi',
        text: `Sizga 6 raqamli tasdiqlash kodi: ${verificationCode}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Email yuborishda xatolik:', error);
        } else {
            console.log('Email yuborildi:', info.response);
        }
    });
};

// Nomzodlar ro‘yxatini olish va ovozlarini ko'rsatish
app.get('/candidates', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, nomzod, ovoz_soni FROM votes');
        res.json(result.rows);
    } catch (err) {
        console.error('Nomzodlarni olishda xatolik:', err);
        res.status(500).send('Nomzodlarni olishda xatolik');
    }
});



// Foydalanuvchi login qilish va ma'lumotlar bazasida tekshirish
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length > 0) {
        const user = result.rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
            userEmail = email;
            res.send({ message: 'Kirish muvaffaqiyatli!', redirectTo: '/vote.html' });
        } else {
            res.status(400).send('Parol noto\'g\'ri.');
        }
    } else {
        res.status(400).send('Email noto\'g\'ri.');
    }
});






app.post('/register', async (req, res) => {
    try {
        const userData = req.body;

        console.log('Keldi foydalanuvchi malumotlari:', userData);

        // Public key mavjudligini tekshirish
        if (!publicKey) {
            return res.status(400).send({
                success: false,
                message: 'Public key mavjud emas.',
            });
        }

        // Bazada foydalanuvchini tekshirish (email, passportNumber, phoneNumber)
        const checkQuery = `
            SELECT * FROM users 
            WHERE email = $1 OR passport_number = $2 OR phone_number = $3
        `;
        const checkValues = [
            userData.email,
            userData.passportNumber,
            userData.phoneNumber,
        ];

        const existingUser = await pool.query(checkQuery, checkValues);

        if (existingUser.rows.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Bu foydalanuvchi allaqachon ro‘yxatdan o‘tgan.',
            });
        }
        

        // Parolni hash qilish
        const hashedPassword = await bcrypt.hash(userData.password, 10); // 10 - salt rounds

        // RSA yordamida ma'lumotni shifrlash
        const encryptedData = crypto.publicEncrypt(
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256',
            },
            Buffer.from(JSON.stringify(userData))
        );

        console.log('Shifrlangan malumot:', encryptedData.toString('base64'));

        // Ma'lumotni bazaga saqlash
        const insertQuery = `
            INSERT INTO users (first_name, last_name, passport_number, phone_number, email, password)
            VALUES ($1, $2, $3, $4, $5, $6)
        `;
        const insertValues = [
            userData.firstName,
            userData.lastName,
            userData.passportNumber,
            userData.phoneNumber,
            userData.email,
            hashedPassword, // Hash qilingan parol
        ];

        await pool.query(insertQuery, insertValues);

        // Login sahifasiga to‘g‘ridan-to‘g‘ri yo‘naltirish
        res.redirect('/login.html');

    } catch (err) {
        console.error('Shifrlashda yoki saqlashda xatolik:', err);
        res.status(500).send({
            success: false,
            message: 'Malumotni saqlashda xatolik yuz berdi.',
        });
    }
});





// Nomzodni tanlang va tasdiqlash kodini yuboring
app.post('/select-candidate', async (req, res) => {
    const { candidateId } = req.body;

    if (!userEmail) {
        return res.status(400).send({ message: 'Foydalanuvchi autentifikatsiya qilinmagan.' });
    }

    try {
        // Tekshirish uchun foydalanuvchini bazadan topish
        const userResult = await pool.query('SELECT ovoz_status FROM users WHERE email = $1', [userEmail]);
        const user = userResult.rows[0];

        // Foydalanuvchi ovoz berganligini tekshirish
        if (user.ovoz_status) {
            return res.status(400).send({ message: 'Siz allaqachon ovoz bergansiz.' });
        }

        // Nomzodni tanlash va tasdiqlash kodini yuborish
        selectedCandidate = candidateId;
        console.log("Tanlangan nomzod ID:", selectedCandidate);

        sendVerificationEmail(userEmail);
        res.send({ message: 'Nomzod tanlandi. Tasdiqlash kodi yuborildi.' });
    } catch (err) {
        console.error('Nomzod tanlashda xatolik:', err);
        res.status(500).send({ message: 'Xatolik yuz berdi.' });
    }
});

// Tasdiqlash kodini tekshirish va ovoz berish
app.post('/verify-code', async (req, res) => {
    const { code } = req.body;

    try {
        // Tekshirish uchun foydalanuvchini bazadan topish
        const userResult = await pool.query('SELECT ovoz_status FROM users WHERE email = $1', [userEmail]);
        const user = userResult.rows[0];

        // Foydalanuvchi ovoz berganligini tekshirish
        if (user.ovoz_status) {
            return res.status(400).send({ message: 'Siz allaqachon ovoz bergansiz.' });
        }

        // Tasdiqlash kodi tekshirish
        if (code === verificationCode) {
            // Ovozni nomzodga qo'shish
            await pool.query('UPDATE votes SET ovoz_soni = ovoz_soni + 1 WHERE id = $1', [selectedCandidate]);

            // Foydalanuvchi ovoz berganligini yangilash va nomzodning ID sini saqlash
        await pool.query(
            'UPDATE users SET ovoz_status = true, nomzod_id = $1 WHERE email = $2',
            [selectedCandidate, userEmail]
        );


            res.send({ message: 'Muvaffaqiyatli ovoz berdingiz!' });
        } else {
            res.status(400).send({ message: 'Noto\'g\'ri tasdiqlash kodi.' });
        }
    } catch (err) {
        console.error('Tasdiqlashda xatolik:', err);
        res.status(500).send({ message: 'Xatolik yuz berdi.' });
    }
});

// JWT secret key
JWT_SECRET_KEY="6f8d8b5d56fa419b750c94fa1ad8e853f4d18a6731cb935f3e5c7cf5ba7a7e7a";

// Admin login route
app.post('/admin/login', [
    body('email').isEmail().withMessage('Email noto\'g\'ri'),
    body('password').isLength({ min: 6 }).withMessage('Parol kamida 6 belgidan iborat bo\'lishi kerak'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
        // Admin authentication
        const adminResult = await client.query('SELECT * FROM admin WHERE email = $1 AND password = $2', [email, password]);
        
        if (adminResult.rows.length > 0) {
            const admin = adminResult.rows[0];
            const token = jwt.sign({ id: admin.id, email: admin.email }, JWT_SECRET_KEY, { expiresIn: '1h' });
            res.json({ message: 'Kirish muvaffaqiyatli!', token });
        } else {
            res.status(400).send('Email yoki parol noto\'g\'ri.');
        }
    } catch (err) {
        console.error('Admin login error:', err);
        res.status(500).send('Serverda xatolik yuz berdi.');
    }
});

// JWT bilan marshrutlarni himoya qilish
const authenticateAdmin = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).send('Token topilmadi');
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET_KEY);
        req.admin = decoded; // So'rovga dekodlangan administrator ma'lumotlarini qo'shing
        next();
    } catch (err) {
        return res.status(401).send('Noto\'g\'ri yoki muddati o\'tgan token');
    }
};

// Administrator paneli marshruti (himoyalangan)
app.get('/admin-panel', authenticateAdmin, async (req, res) => {
    try {
        const candidatesResult = await client.query('SELECT id, nomzod, ovoz_soni FROM votes');
        const usersResult = await client.query('SELECT first_name, last_name, email, nomzod_id FROM users');
        
        const response = {
            candidates: candidatesResult.rows,
            users: usersResult.rows
        };

        res.json(response);
    } catch (err) {
        console.error('Error:', err);
        res.status(500).send('Serverda xatolik yuz berdi.');
    }
});

// Server ishga tushganda adminni tekshirish va saqlash
checkAndInsertAdmin();
// Serverni ishga tushurish
app.listen(port, () => {
    console.log(`Server ishlayapti: http://localhost:${port}`);
});

