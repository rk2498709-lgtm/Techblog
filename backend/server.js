import 'dotenv/config';
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import fs from 'fs';

const app = express();
const PORT = process.env.PORT || 4000;
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) throw new Error('Set JWT_SECRET (32+ characters) in backend/.env');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:5173' }));
app.use(express.json({ limit: '1mb' }));
const uploadDir = path.resolve('uploads');
fs.mkdirSync(uploadDir, { recursive: true });
app.use('/uploads', express.static(uploadDir));

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
app.use((err, _req, res, _next) => res.status(400).json({ error: err.message || 'Request failed' }));
await mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/techblog');
app.listen(PORT, () => console.log(`API running at http://localhost:${PORT}`));
