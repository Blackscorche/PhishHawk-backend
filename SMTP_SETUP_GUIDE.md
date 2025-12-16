# SMTP Configuration Guide for CantPhishMe

## Quick Setup

Add these lines to your `.env` file in the `PhishHawk-backend` folder:

```env
# SMTP Configuration (Required for sending emails to hosting providers)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password-here
SMTP_FROM="CantPhishMe <your-email@gmail.com>"
SMTP_SECURE=false
```

## Gmail Setup (Recommended)

### Step 1: Enable 2-Step Verification
1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Enable "2-Step Verification" if not already enabled

### Step 2: Generate App Password
1. Go to [App Passwords](https://myaccount.google.com/apppasswords)
2. Select "Mail" and "Other (Custom name)"
3. Enter "CantPhishMe" as the name
4. Click "Generate"
5. Copy the 16-character password (no spaces)

### Step 3: Add to .env
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=abcd efgh ijkl mnop  # Use the app password (remove spaces)
SMTP_FROM="CantPhishMe <your-email@gmail.com>"
SMTP_SECURE=false
```

## ProtonMail Setup

### Important Notes:
- **ProtonMail Free accounts**: SMTP access is limited. You may need ProtonMail Plus or higher for full SMTP functionality.
- **App Password Required**: You MUST use an app password, not your regular ProtonMail password.

### Step 1: Enable SMTP in ProtonMail
1. Log in to [ProtonMail](https://mail.proton.me)
2. Go to Settings → All settings → Go to Settings
3. Navigate to "Security" → "App passwords"
4. Create a new app password for "Mail" or "SMTP"
5. Copy the generated password

### Step 2: Add to .env
```env
SMTP_HOST=mail.proton.me
SMTP_PORT=587
SMTP_USER=your-email@proton.me
SMTP_PASS=your-app-password-here
SMTP_FROM="CantPhishMe <your-email@proton.me>"
SMTP_SECURE=false
```

### Alternative ProtonMail Settings (if mail.proton.me doesn't work):
```env
SMTP_HOST=127.0.0.1
SMTP_PORT=1025
SMTP_USER=your-email@proton.me
SMTP_PASS=your-app-password
SMTP_FROM="CantPhishMe <your-email@proton.me>"
SMTP_SECURE=false
```

**Note**: ProtonMail free accounts may have restrictions. Consider using ProtonMail Bridge for better SMTP support, or use a different email provider for sending abuse reports.

## Other Email Providers

### Outlook/Hotmail
```env
SMTP_HOST=smtp-mail.outlook.com
SMTP_PORT=587
SMTP_USER=your-email@outlook.com
SMTP_PASS=your-password
SMTP_FROM="CantPhishMe <your-email@outlook.com>"
SMTP_SECURE=false
```

### Yahoo Mail
```env
SMTP_HOST=smtp.mail.yahoo.com
SMTP_PORT=587
SMTP_USER=your-email@yahoo.com
SMTP_PASS=your-app-password
SMTP_FROM="CantPhishMe <your-email@yahoo.com>"
SMTP_SECURE=false
```

### Custom SMTP Server
```env
SMTP_HOST=mail.yourdomain.com
SMTP_PORT=587
SMTP_USER=noreply@yourdomain.com
SMTP_PASS=your-password
SMTP_FROM="CantPhishMe <noreply@yourdomain.com>"
SMTP_SECURE=false
```

## Important Notes

1. **Never commit .env to git** - It contains sensitive credentials
2. **Use App Passwords** - Don't use your regular email password for Gmail/Yahoo
3. **Restart backend** - After adding SMTP config, restart your backend server
4. **Test it** - Try sending a report after configuration

## Verification

After adding SMTP config, restart your backend and check:
- Backend logs should show: `SMTP configured: true`
- API status endpoint: `/api/phishing/api-status` should show `smtp: { configured: true }`
- Try sending a report - it should work now!

## Troubleshooting

### "SMTP not configured" error
- Check that all SMTP variables are in `.env` file
- Make sure there are no spaces around `=` signs
- Restart backend server after adding config

### "Authentication failed" error
- For Gmail: Make sure you're using an App Password, not your regular password
- Check that 2-Step Verification is enabled
- Verify SMTP_USER matches your email exactly

### "Connection timeout" error
- Check SMTP_HOST is correct
- Verify SMTP_PORT (587 for most providers)
- Check firewall/network settings

### "Email sent but not received"
- Check spam/junk folder
- Verify SMTP_FROM email is valid
- Check recipient email addresses are correct

