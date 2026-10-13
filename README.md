# ShopEarn live starter (manual UPI workflow)

This is a **deployable application starter**, not a payment processor or a fully launched business. It includes:
- User registration/login with hashed passwords
- Product listing and demo checkout/order records
- Admin-configurable commission percentage, hold period, minimum withdrawal, UPI ID and QR upload
- Commission ledger: 6% default, available after 30 days
- Withdrawal requests and admin approve/reject workflow
- SQLite database and server-side sessions

## Important payment limitation
A UPI ID or QR code only helps a payer open their UPI app and pay. It does **not** prove a payment happened, and it does not let this app send payouts automatically. For customer payments, admin must verify payment in their bank/UPI app before confirming an order. For payouts, admin must send money separately from their bank/UPI app and only then mark a request as paid. For automated collection or payouts, integrate a regulated payment provider with merchant onboarding/KYC and verified webhooks.

## Run locally
1. Install Node.js 20 or newer.
2. Copy `.env.example` to `.env`.
3. Set a long random `SESSION_SECRET`.
4. Create a bcrypt password hash for your admin password:
   ```bash
   node -e "require('bcryptjs').hash('PUT-A-STRONG-PASSWORD-HERE', 12).then(console.log)"
   ```
   Put the printed value in `ADMIN_PASSWORD_HASH`. Choose your own strong password; do not use the demo password.
5. Run:
   ```bash
   npm install
   npm start
   ```
6. Open `http://localhost:3000`.

## QR upload
Sign in as admin, open Admin Settings, and upload your own static UPI QR image. Do not upload someone else's QR. The QR image is saved under `public/uploads/`.

## Before going live
- Deploy to a host with HTTPS and persistent disk or switch SQLite to a managed database.
- Set `NODE_ENV=production`, secure secrets, and a strong unique admin password.
- Add email/phone verification, password reset, CSRF protection, audit logs, backups, privacy policy, terms, refund rules and support contact.
- Add server-side payment verification or a payment provider before marking orders paid.
- Have a qualified professional review Indian legal, tax, consumer protection, KYC/AML and payment-provider requirements.
- Do not promise returns or commissions unless backed by genuine product sales and a sustainable business model.

This starter intentionally does **not** store bank passwords, UPI PINs, OTPs, or card details.
