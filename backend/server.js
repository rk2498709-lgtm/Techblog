import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, '.env') });

import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import fs from 'fs';

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || '5cbf96597e2acf1ca7c731832593de5f4e0f366ce2d0c0670b7063e11763b23e8965d7de2197eba95ece06887c99c8bf';

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept']
}));
app.options('*', cors());
app.use(express.json({ limit: '1mb' }));

const uploadDir = process.env.VERCEL ? path.join('/tmp', 'uploads') : path.resolve('uploads');
try { fs.mkdirSync(uploadDir, { recursive: true }); } catch {}
app.use('/uploads', express.static(uploadDir));

// Database connection helper for local and serverless environments
let isConnected = false;
async function connectDB() {
  if (isConnected || mongoose.connection.readyState >= 1) {
    isConnected = true;
    return;
  }
  let uri = (process.env.MONGO_URI || '').trim();
  if (!uri) throw new Error('MONGO_URI is missing. Please set it in your environment variables.');
  
  // Strip accidental quotes or "MONGO_URI=" prefix if pasted into Vercel
  if ((uri.startsWith('"') && uri.endsWith('"')) || (uri.startsWith("'") && uri.endsWith("'"))) {
    uri = uri.slice(1, -1).trim();
  }
  if (uri.startsWith('MONGO_URI=')) {
    uri = uri.replace(/^MONGO_URI=\s*/, '').trim();
  }

  await mongoose.connect(uri);
  isConnected = true;
}

app.use(async (_req, _res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    next(err);
  }
});

const userSchema = new mongoose.Schema({ email: { type: String, unique: true }, password: String, role: { type: String, default: 'admin' } });
const User = mongoose.model('User', userSchema);
const postSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true }, slug: { type: String, unique: true, required: true },
  excerpt: String, content: String, category: { type: String, default: 'Technology & Innovation' },
  tags: [String], author: { type: String, default: 'Editorial Team' }, image: String,
  status: { type: String, enum: ['draft', 'published'], default: 'draft' },
  publishAt: Date, featured: { type: Boolean, default: false }, seoTitle: String, metaDescription: String
}, { timestamps: true });
const Post = mongoose.model('Post', postSchema);
const categorySchema = new mongoose.Schema({ name: { type: String, required: true, unique: true } });
const Category = mongoose.model('Category', categorySchema);
const visible = { status: 'published', $or: [{ publishAt: null }, { publishAt: { $lte: new Date() } }] };
const slugify = text => String(text || '').toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace(/^Bearer /, '');
    const user = jwt.verify(token, process.env.JWT_SECRET);
    if (user.role !== 'admin') return res.sendStatus(403);
    req.user = user; next();
  } catch { res.status(401).json({ error: 'Please sign in again.' }); }
}
app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.post('/api/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false }), async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email || '').toLowerCase() });
  if (!user || !(await bcrypt.compare(String(req.body.password || ''), user.password))) return res.status(401).json({ error: 'Invalid email or password' });
  res.json({ token: jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '8h' }) });
});
app.get('/api/categories', async (_req, res) => res.json(await Category.find().sort('name')));
app.post('/api/categories', auth, async (req, res) => {
  try { res.status(201).json(await Category.create({ name: String(req.body.name || '').trim() })); }
  catch { res.status(400).json({ error: 'Category already exists or name is missing' }); }
});
app.delete('/api/categories/:id', auth, async (req, res) => { await Category.findByIdAndDelete(req.params.id); res.json({ ok: true }); });
app.get('/api/posts', async (req, res) => {
  const page = Math.max(1, Number(req.query.page) || 1), limit = 6;
  const filter = { ...visible };
  if (req.query.category) filter.category = req.query.category;
  if (req.query.search) { const q = String(req.query.search).slice(0, 100).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); filter.$and = [{ $or: [{ title: { $regex: q, $options: 'i' } }, { excerpt: { $regex: q, $options: 'i' } }] }]; }
  const [posts, total] = await Promise.all([Post.find(filter).sort({ publishAt: -1, createdAt: -1 }).skip((page - 1) * limit).limit(limit), Post.countDocuments(filter)]);
  res.json({ posts, total, pages: Math.ceil(total / limit), page });
});
app.get('/api/posts/:slug', async (req, res) => {
  const post = await Post.findOne({ slug: req.params.slug, ...visible });
  if (!post) return res.status(404).json({ error: 'Article not found' });
  res.json(post);
});
app.get('/api/admin/posts', auth, async (_req, res) => res.json(await Post.find().sort({ updatedAt: -1 })));
app.post('/api/admin/posts', auth, async (req, res) => {
  try {
    const body = req.body;
    if (!body.title?.trim()) return res.status(400).json({ error: 'Title is required' });
    const slug = slugify(body.slug || body.title);
    if (!slug) return res.status(400).json({ error: 'Invalid slug' });
    const post = await Post.create({ ...pickPost(body), slug });
    res.status(201).json(post);
  } catch (e) { res.status(400).json({ error: e.code === 11000 ? 'URL slug already exists' : 'Unable to create post' }); }
});
app.put('/api/admin/posts/:id', auth, async (req, res) => {
  try {
    const data = pickPost(req.body);
    if (req.body.slug) data.slug = slugify(req.body.slug);
    const post = await Post.findByIdAndUpdate(req.params.id, data, { new: true, runValidators: true });
    if (!post) return res.sendStatus(404);
    res.json(post);
  } catch { res.status(400).json({ error: 'Unable to update (check slug)' }); }
});
app.delete('/api/admin/posts/:id', auth, async (req, res) => { await Post.findByIdAndDelete(req.params.id); res.json({ ok: true }); });
function pickPost(b) {
  return { title: b.title, excerpt: b.excerpt || '', content: b.content || '', category: b.category || 'Technology & Innovation',
    tags: Array.isArray(b.tags) ? b.tags : [], author: b.author || 'Editorial Team', image: b.image || '',
    status: b.status === 'published' ? 'published' : 'draft', publishAt: b.publishAt || null,
    featured: !!b.featured, seoTitle: b.seoTitle || '', metaDescription: b.metaDescription || '' };
}
const storage = multer.diskStorage({ destination: uploadDir, filename: (_req, file, cb) => cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${path.extname(file.originalname).toLowerCase()}`) });
const upload = multer({ storage, limits: { fileSize: 3 * 1024 * 1024 }, fileFilter: (_req, file, cb) => cb(null, ['image/png', 'image/jpeg', 'image/webp', 'image/gif'].includes(file.mimetype)) });
app.post('/api/admin/upload', auth, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Choose a JPG, PNG, WebP or GIF under 3 MB' });
  res.json({ url: `/uploads/${req.file.filename}` });
});
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Request failed' });
});

if (!process.env.VERCEL) {
  try {
    await connectDB();
    app.listen(PORT, () => console.log(`API running at http://localhost:${PORT}`));
  } catch (err) {
    console.error('Database connection failed on startup:', err.message);
    app.listen(PORT, () => console.log(`API running without DB at http://localhost:${PORT}`));
  }
}

export default app;
