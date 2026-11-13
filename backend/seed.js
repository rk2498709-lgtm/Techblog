import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, '.env') });

import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
const email = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const password = process.env.ADMIN_PASSWORD || '';
if (!email.includes('@') || password.length < 12) throw new Error('Set ADMIN_EMAIL and ADMIN_PASSWORD (12+ characters) in .env');
await mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/techblog');
const User = mongoose.model('User', new mongoose.Schema({ email: { type: String, unique: true }, password: String, role: String }));
const Category = mongoose.model('Category', new mongoose.Schema({ name: { type: String, unique: true } }));
await User.updateOne({ email }, { $set: { password: await bcrypt.hash(password, 12), role: 'admin' } }, { upsert: true });
for (const name of ['Software Development', 'Artificial Intelligence & Machine Learning', 'Web & Mobile App Development', 'Technology & Innovation', 'Cybersecurity', 'Cloud Computing', 'Industry Insights']) await Category.updateOne({ name }, { $setOnInsert: { name } }, { upsert: true });
console.log(`Admin ready: ${email}. Password is the value in your .env file.`);
await mongoose.disconnect();
