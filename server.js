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
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const cors = require('cors');

const { Pool } = require('pg');
app.use(cors()); // CORSni yoqish

const port = 3000;

// PostgreSQL bazasi ulanishi
const client = new Client({
  user: 'postgres',  // PostgreSQL foydalanuvchi nomi
  host: 'localhost',
  database: 'ovozDb',
  password: 'akmal625',  // PostgreSQL parol
  port: 5432,
});
client.connect();

// Sertifikatlar (OpenSSL bilan yaratilgan sertifikatlar)
// const options = {
//     key: fs.readFileSync('D:/Ovoz/Ovoz/key.pem'), // Maxfiy kalit
//     cert: fs.readFileSync('D:/Ovoz/Ovoz/cert.crt') // Sertifikat
// };

// Wifi orqali ulanish uchun baza
// const pool = new Pool({
//     user: 'postgres',
//     host: 'localhost',
//     database: 'ovozDb',
//     password: 'akmal625',
//     port: 5432,
// });
// pool.connect();

// Body parser
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true })); // URL orqali kodlangan ma'lumotlarni qo'llash
app.use(express.json()); // JSON formatidagi kiruvchi ma'lumotlarni qo'llab-quvvatlash

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
            console.log('Admin allaqachon mavjud.');
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
        const result = await client.query('SELECT id, nomzod, ovoz_soni FROM votes');
        res.json(result.rows);
    } catch (err) {
        console.error('Nomzodlarni olishda xatolik:', err);
        res.status(500).send('Nomzodlarni olishda xatolik');
    }
});



// Foydalanuvchi login qilish va ma'lumotlar bazasida tekshirish
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);

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


// Parolni hash qilish
app.post('/register', async (req, res) => {
    const { firstName, lastName, passportNumber, phoneNumber, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10); // 10 - salt rounds

    try {
        await client.query(
            'INSERT INTO users (first_name, last_name, passport_number, phone_number, email, password) VALUES ($1, $2, $3, $4, $5, $6)',
            [firstName, lastName, passportNumber, phoneNumber, email, hashedPassword]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('Ro\'yxatdan o\'tishda xatolik:', err);
        res.json({ success: false, message: 'Foydalanuvchi yaratishda xatolik yuz berdi.' });
    }
});


// Select candidate and send verification code
app.post('/select-candidate', async (req, res) => {
    const { candidateId } = req.body;

    if (!userEmail) {
        return res.status(400).send({ message: 'Foydalanuvchi autentifikatsiya qilinmagan.' });
    }

    try {
        // Tekshirish uchun foydalanuvchini bazadan topish
        const userResult = await client.query('SELECT ovoz_status FROM users WHERE email = $1', [userEmail]);
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
        const userResult = await client.query('SELECT ovoz_status FROM users WHERE email = $1', [userEmail]);
        const user = userResult.rows[0];

        // Foydalanuvchi ovoz berganligini tekshirish
        if (user.ovoz_status) {
            return res.status(400).send({ message: 'Siz allaqachon ovoz bergansiz.' });
        }

        // Tasdiqlash kodi tekshirish
        if (code === verificationCode) {
            // Ovozni nomzodga qo'shish
            await client.query('UPDATE votes SET ovoz_soni = ovoz_soni + 1 WHERE id = $1', [selectedCandidate]);

            // Foydalanuvchi ovoz berganligini yangilash va nomzodning ID sini saqlash
        await client.query(
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

// Protecting routes with JWT
const authenticateAdmin = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).send('Token topilmadi');
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET_KEY);
        req.admin = decoded; // Attach decoded admin info to the request
        next();
    } catch (err) {
        return res.status(401).send('Noto\'g\'ri yoki muddati o\'tgan token');
    }
};

// Admin panel route (protected)
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

