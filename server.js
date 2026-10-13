require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const dataDir = path.join(__dirname, "data");
const uploadDir = path.join(__dirname, "public", "uploads");
fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });
const db = new Database(path.join(dataDir, "shopearn.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, price_paise INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, product_id INTEGER NOT NULL, amount_paise INTEGER NOT NULL, commission_paise INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'payment_pending', payment_ref TEXT, created_at TEXT NOT NULL, paid_at TEXT, FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(product_id) REFERENCES products(id));
CREATE TABLE IF NOT EXISTS withdrawals (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, amount_paise INTEGER NOT NULL, upi_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', admin_note TEXT DEFAULT '', created_at TEXT NOT NULL, reviewed_at TEXT, FOREIGN KEY(user_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ledger (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, order_id INTEGER NOT NULL, amount_paise INTEGER NOT NULL, available_at TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(order_id), FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(order_id) REFERENCES orders(id));
`);
const settingDefaults = {
  commission_percent: String(Number(process.env.COMMISSION_PERCENT || 6)),
  hold_days: String(Number(process.env.HOLD_DAYS || 30)),
  min_withdrawal_paise: String(Math.round(Number(process.env.MIN_WITHDRAWAL || 30) * 100)),
  merchant_upi: process.env.MERCHANT_UPI_ID || "",
  merchant_name: process.env.MERCHANT_NAME || "ShopEarn",
  qr_path: ""
};
for (const [k,v] of Object.entries(settingDefaults)) db.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)").run(k,v);
const seed = db.prepare("SELECT COUNT(*) AS n FROM products").get().n;
if (!seed) {
  const insert = db.prepare("INSERT INTO products(name,description,price_paise) VALUES(?,?,?)");
  insert.run("Smart Watch", "Everyday smart watch", 500000);
  insert.run("Wireless Earbuds", "Wireless audio earbuds", 350000);
  insert.run("Classic T-Shirt", "Everyday cotton t-shirt", 120000);
  insert.run("Mobile Cover", "Protective phone cover", 79900);
}
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], scriptSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", "data:"] } } }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(express.json({ limit: "20kb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.db", dir: dataDir }),
  secret: process.env.SESSION_SECRET || "dev-only-change-me-before-deploying",
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 1000*60*60*8 }
}));
app.use(rateLimit({ windowMs: 15*60*1000, limit: 250, standardHeaders: true, legacyHeaders: false }));
app.use("/uploads", express.static(uploadDir));
app.use(express.static(path.join(__dirname, "public")));

const now = () => new Date().toISOString();
const setting = key => db.prepare("SELECT value FROM settings WHERE key=?").get(key)?.value ?? "";
const setSetting = (key,value) => db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(key,String(value));
const rupees = paise => Math.round(Number(paise));
const isAdmin = req => req.session && req.session.admin === true;
const requireUser = (req,res,next) => req.session?.userId ? next() : res.status(401).json({error:"Please sign in first."});
const requireAdmin = (req,res,next) => isAdmin(req) ? next() : res.status(401).json({error:"Admin login required."});
const safeUser = id => db.prepare("SELECT id,username,created_at FROM users WHERE id=?").get(id);
function availableBalance(userId) {
  const due = db.prepare("SELECT COALESCE(SUM(amount_paise),0) AS n FROM ledger WHERE user_id=? AND available_at<=?").get(userId,now()).n;
  const reserved = db.prepare("SELECT COALESCE(SUM(amount_paise),0) AS n FROM withdrawals WHERE user_id=? AND status IN ('pending','approved')").get(userId).n;
  return Math.max(0,due-reserved);
}
function totals(userId) {
  const earned = db.prepare("SELECT COALESCE(SUM(amount_paise),0) n FROM ledger WHERE user_id=?").get(userId).n;
  const pending = db.prepare("SELECT COALESCE(SUM(amount_paise),0) n FROM ledger WHERE user_id=? AND available_at>?").get(userId,now()).n;
  return {earned, pending, available:availableBalance(userId)};
}
const upload = multer({storage:multer.diskStorage({
  destination:(_,__,cb)=>cb(null,uploadDir),
  filename:(_,file,cb)=>cb(null,crypto.randomBytes(12).toString("hex")+path.extname(file.originalname).toLowerCase())
}), limits:{fileSize:2*1024*1024}, fileFilter:(_,file,cb)=>cb(null,["image/png","image/jpeg","image/webp"].includes(file.mimetype))});

app.get("/api/config", (req,res)=>res.json({merchantName:setting("merchant_name"), merchantUpi:setting("merchant_upi"), qrPath:setting("qr_path"), commissionPercent:Number(setting("commission_percent")), holdDays:Number(setting("hold_days")), minWithdrawalRupees:Number(setting("min_withdrawal_paise"))/100}));
app.post("/api/register", async (req,res)=>{
  const username=String(req.body.username||"").trim().toLowerCase(), password=String(req.body.password||"");
  if(!/^[a-z0-9_]{3,24}$/.test(username)||password.length<10) return res.status(400).json({error:"Username must be 3–24 letters/numbers/underscore; password must be at least 10 characters."});
  try { const hash=await bcrypt.hash(password,12); const result=db.prepare("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)").run(username,hash,now()); req.session.userId=Number(result.lastInsertRowid); res.json({user:safeUser(req.session.userId)}); }
  catch(e){res.status(409).json({error:"That username may already be in use."});}
});
app.post("/api/login", async (req,res)=>{
  const username=String(req.body.username||"").trim().toLowerCase(), password=String(req.body.password||"");
  const user=db.prepare("SELECT * FROM users WHERE username=?").get(username);
  if(!user||!(await bcrypt.compare(password,user.password_hash))) return res.status(401).json({error:"Invalid username or password."});
  req.session.regenerate(err=>{if(err)return res.status(500).json({error:"Could not start session."});req.session.userId=user.id;res.json({user:safeUser(user.id)});});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({user:req.session?.userId?safeUser(req.session.userId):null,admin:isAdmin(req)}));
app.get("/api/products",(req,res)=>res.json(db.prepare("SELECT id,name,description,price_paise FROM products WHERE active=1").all()));
app.post("/api/orders",requireUser,(req,res)=>{
  const product=db.prepare("SELECT * FROM products WHERE id=? AND active=1").get(Number(req.body.productId));
  if(!product)return res.status(404).json({error:"Product not found."});
  const rate=Number(setting("commission_percent")); const commission=Math.round(product.price_paise*rate/100);
  const result=db.prepare("INSERT INTO orders(user_id,product_id,amount_paise,commission_paise,status,created_at) VALUES(?,?,?,?,?,?)").run(req.session.userId,product.id,product.price_paise,commission,"payment_pending",now());
  res.json({orderId:Number(result.lastInsertRowid),amountPaise:product.price_paise,commissionPaise:commission,merchantUpi:setting("merchant_upi"),merchantName:setting("merchant_name"),qrPath:setting("qr_path"),message:"Order is pending payment verification. Do not mark paid until you verify the payment in your UPI/bank account."});
});
app.get("/api/orders",requireUser,(req,res)=>res.json(db.prepare("SELECT o.id,o.amount_paise,o.commission_paise,o.status,o.created_at,o.paid_at,p.name product_name FROM orders o JOIN products p ON p.id=o.product_id WHERE o.user_id=? ORDER BY o.id DESC").all(req.session.userId)));
app.get("/api/wallet",requireUser,(req,res)=>{
  const t=totals(req.session.userId);
  const ledger=db.prepare("SELECT l.amount_paise,l.available_at,l.created_at,p.name product_name,o.id order_id FROM ledger l JOIN orders o ON o.id=l.order_id JOIN products p ON p.id=o.product_id WHERE l.user_id=? ORDER BY l.id DESC").all(req.session.userId);
  res.json({...t,ledger});
});
app.post("/api/withdrawals",requireUser,(req,res)=>{
  const upi=String(req.body.upiId||"").trim(), amount=Math.round(Number(req.body.amountRupees)*100), min=Number(setting("min_withdrawal_paise"));
  if(!/^[\w.-]{2,256}@[a-zA-Z]{2,64}$/.test(upi))return res.status(400).json({error:"Enter a valid-looking UPI ID."});
  if(!Number.isFinite(amount)||amount<min)return res.status(400).json({error:`Minimum withdrawal is ₹${min/100}.`});
  if(amount>availableBalance(req.session.userId))return res.status(400).json({error:"Amount exceeds eligible available balance."});
  const result=db.prepare("INSERT INTO withdrawals(user_id,amount_paise,upi_id,status,created_at) VALUES(?,?,?,'pending',?)").run(req.session.userId,amount,upi,now());
  res.json({id:Number(result.lastInsertRowid),status:"pending",message:"Request sent for manual admin review. No money has been transferred."});
});
app.get("/api/withdrawals",requireUser,(req,res)=>res.json(db.prepare("SELECT id,amount_paise,upi_id,status,admin_note,created_at,reviewed_at FROM withdrawals WHERE user_id=? ORDER BY id DESC").all(req.session.userId)));
app.post("/api/admin/login",async(req,res)=>{
  const username=process.env.ADMIN_USERNAME||"admin", hash=process.env.ADMIN_PASSWORD_HASH||"";
  if(!hash||String(req.body.username||"")!==username||!(await bcrypt.compare(String(req.body.password||""),hash)))return res.status(401).json({error:"Invalid admin credentials. Configure ADMIN_PASSWORD_HASH in .env."});
  req.session.regenerate(err=>{if(err)return res.status(500).json({error:"Could not start admin session."});req.session.admin=true;res.json({ok:true});});
});
app.get("/api/admin/summary",requireAdmin,(req,res)=>res.json({
  orders:db.prepare("SELECT COUNT(*) n FROM orders").get().n,
  pendingOrders:db.prepare("SELECT COUNT(*) n FROM orders WHERE status='payment_pending'").get().n,
  pendingWithdrawals:db.prepare("SELECT COUNT(*) n FROM withdrawals WHERE status='pending'").get().n,
  ordersList:db.prepare("SELECT o.id,o.amount_paise,o.commission_paise,o.status,o.created_at,u.username,p.name product_name FROM orders o JOIN users u ON u.id=o.user_id JOIN products p ON p.id=o.product_id ORDER BY o.id DESC LIMIT 100").all(),
  withdrawals:db.prepare("SELECT w.id,w.amount_paise,w.upi_id,w.status,w.admin_note,w.created_at,u.username FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC LIMIT 100").all(),
  config:{commissionPercent:Number(setting("commission_percent")),holdDays:Number(setting("hold_days")),minWithdrawalRupees:Number(setting("min_withdrawal_paise"))/100,merchantUpi:setting("merchant_upi"),merchantName:setting("merchant_name"),qrPath:setting("qr_path")}
}));
app.post("/api/admin/settings",requireAdmin,upload.single("qr"),(req,res)=>{
  const rate=Number(req.body.commissionPercent), days=Number(req.body.holdDays), min=Number(req.body.minWithdrawalRupees), upi=String(req.body.merchantUpi||"").trim(), name=String(req.body.merchantName||"ShopEarn").trim();
  if(!Number.isFinite(rate)||rate<0||rate>100||!Number.isInteger(days)||days<0||days>365||!Number.isFinite(min)||min<1)return res.status(400).json({error:"Check commission, hold days and minimum withdrawal."});
  setSetting("commission_percent",rate);setSetting("hold_days",days);setSetting("min_withdrawal_paise",Math.round(min*100));setSetting("merchant_upi",upi);setSetting("merchant_name",name);
  if(req.file)setSetting("qr_path","/uploads/"+req.file.filename);
  res.json({ok:true});
});
app.post("/api/admin/orders/:id/confirm-payment",requireAdmin,(req,res)=>{
  const order=db.prepare("SELECT * FROM orders WHERE id=?").get(Number(req.params.id));
  if(!order)return res.status(404).json({error:"Order not found."});
  if(order.status!=="payment_pending")return res.status(400).json({error:"Order is not awaiting payment."});
  const paidAt=now(), availableAt=new Date(Date.now()+Number(setting("hold_days"))*86400000).toISOString();
  const tx=db.transaction(()=>{
    db.prepare("UPDATE orders SET status='paid',paid_at=?,payment_ref=? WHERE id=?").run(paidAt,String(req.body.paymentRef||"").slice(0,100),order.id);
    db.prepare("INSERT INTO ledger(user_id,order_id,amount_paise,available_at,created_at) VALUES(?,?,?,?,?)").run(order.user_id,order.id,order.commission_paise,availableAt,paidAt);
  });tx();res.json({ok:true,message:"Payment marked verified and commission ledger created."});
});
app.post("/api/admin/withdrawals/:id/review",requireAdmin,(req,res)=>{
  const status=String(req.body.status||"");if(!["approved","rejected","paid"].includes(status))return res.status(400).json({error:"Status must be approved, rejected, or paid."});
  const w=db.prepare("SELECT * FROM withdrawals WHERE id=?").get(Number(req.params.id));if(!w)return res.status(404).json({error:"Request not found."});
  if(w.status==="paid"||w.status==="rejected")return res.status(400).json({error:"This request is already closed."});
  if(status==="paid"&&w.status!=="approved")return res.status(400).json({error:"Approve first, send the payment manually, then mark paid."});
  if(status==="approved"&&w.status!=="pending")return res.status(400).json({error:"Only pending requests can be approved."});
  if(status==="approved"&&w.amount_paise>availableBalance(w.user_id))return res.status(400).json({error:"Not enough eligible balance now."});
  db.prepare("UPDATE withdrawals SET status=?,admin_note=?,reviewed_at=? WHERE id=?").run(status,String(req.body.note||"").slice(0,500),now(),w.id);
  res.json({ok:true,message:status==="paid"?"Marked paid. Ensure transfer was completed externally.":"Request updated."});
});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`ShopEarn running on http://localhost:${PORT}`));
