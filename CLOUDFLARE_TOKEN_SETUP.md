# Cloudflare API Token Setup Guide

This guide shows you exactly how to configure your Cloudflare API Token for Phase 2: Enforcement in the PhishHawk flowchart.

## What the Token Needs to Do

The PhishHawk system needs to:
1. **Check domain registration** - See if domains are registered with Cloudflare
2. **Lock domains** - Prevent domain transfers (registrar API)
3. **Pause DNS zones** - Stop DNS resolution for malicious domains
4. **Manage zones** - Access zone information

## Step-by-Step Token Configuration

### Step 1: Create API Token

1. Go to: https://dash.cloudflare.com/profile/api-tokens
2. Click **"Create Token"**
3. You can either:
   - Use a template (recommended: "Edit zone DNS")
   - Create a custom token (more secure)

### Step 2: Configure Permissions

For **Custom Token**, configure these permissions:

#### Permission 1: Zone DNS - Edit
- **Permissions**: 
  - First dropdown: `Zone`
  - Second dropdown: `DNS`
  - Third dropdown: `Edit`
- **Why**: Needed to pause DNS zones (stops domain resolution)

#### Permission 2: Zone - Read (Optional but recommended)
- **Permissions**:
  - First dropdown: `Zone`
  - Second dropdown: `Zone`
  - Third dropdown: `Read`
- **Why**: Needed to check if domain exists in your Cloudflare account

#### Permission 3: Account - Registrar - Edit (If available)
- **Permissions**:
  - First dropdown: `Account`
  - Second dropdown: `Registrar`
  - Third dropdown: `Edit`
- **Why**: Needed to lock domain registrations
- **Note**: This may not be available in all Cloudflare plans. If not available, the system will still work for DNS pausing.

### Step 3: Configure Zone Resources

**Option A: All Zones (Easier)**
- **Include**: `All zones`
- **Why**: Works for any domain in your account

**Option B: Specific Zones (More Secure)**
- **Include**: `Specific zone`
- **Select zone**: Choose the specific domain(s) you want to manage
- **Why**: Limits token to only specific domains (more secure)

**Recommendation**: Start with "All zones" for testing, then restrict to specific zones later.

### Step 4: Client IP Address Filtering (Optional)

**For Production (Recommended)**:
- **Operator**: `is in`
- **Value**: Your server's IP address (e.g., `192.168.1.100`)
- **Why**: Limits token usage to your server only (more secure)

**For Development**:
- Leave as default (all IPs)
- **Why**: Easier for testing from different locations

### Step 5: Create and Copy Token

1. Click **"Continue to summary"**
2. Review your token permissions
3. Click **"Create Token"**
4. **IMPORTANT**: Copy the token immediately (you won't be able to see it again!)
5. The token will look like: `AbCdEf123456789...` (long string)

### Step 6: Add to .env File

Add the token to your `.env` file:

```env
# Cloudflare API Token (Recommended - more secure)
CLOUDFLARE_API_TOKEN=your_token_here_AbCdEf123456789...

# OR use Global API Key (Legacy method - still works)
# CLOUDFLARE_API_KEY=your_global_api_key_here
# CLOUDFLARE_EMAIL=your_email@example.com

# Account ID (Required for both methods)
CLOUDFLARE_ACCOUNT_ID=your_account_id_here
```

**Note**: You can use EITHER:
- **API Token** (recommended) - Just need `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID`
- **Global API Key** (legacy) - Need `CLOUDFLARE_API_KEY` + `CLOUDFLARE_EMAIL` + `CLOUDFLARE_ACCOUNT_ID`

## Getting Your Account ID

1. Log in to Cloudflare dashboard
2. Select any domain/website
3. Scroll down to the right sidebar
4. Find **"Account ID"** under the **"API"** section
5. Copy the Account ID

## Minimum Required Permissions Summary

For the PhishHawk system to work, your token needs:

✅ **Zone DNS - Edit** (Required)
- To pause DNS zones

✅ **Zone - Read** (Recommended)
- To check if domains exist

✅ **Account - Registrar - Edit** (If available)
- To lock domain registrations
- May not be available on all plans

## Testing Your Token

After adding the token to `.env`, test it:

1. Start your server:
   ```bash
   npm run dev
   ```

2. Submit a test domain:
   ```bash
   curl -X POST http://localhost:5000/api/phishing \
     -H "Content-Type: application/json" \
     -d '{"url": "https://test-domain.com"}'
   ```

3. Check the logs for:
   - "Cloudflare API authentication failed" = Token issue
   - "Domain not registered with Cloudflare" = Domain not in your account (expected)
   - "Domain takedown initiated successfully" = Token working! ✅

## Troubleshooting

### Error: "Cloudflare API authentication failed"
- **Check**: Token is correctly copied (no extra spaces)
- **Check**: Token hasn't been revoked
- **Check**: Account ID is correct

### Error: "Insufficient permissions"
- **Fix**: Add "Zone DNS - Edit" permission
- **Fix**: Make sure token has access to the zone

### Error: "Domain not found in Cloudflare account"
- **This is normal**: The domain must be registered/managed through Cloudflare
- **Note**: The system will still log the domain for review

### Token Not Working?
- Try using Global API Key instead (legacy method)
- Check Cloudflare dashboard → API Tokens → Verify token is active
- Regenerate token if needed

## Security Best Practices

1. ✅ **Use API Tokens** instead of Global API Keys (more secure)
2. ✅ **Restrict to specific zones** when possible
3. ✅ **Use IP filtering** in production
4. ✅ **Rotate tokens regularly**
5. ✅ **Never commit tokens to Git** (already in .gitignore)

## Visual Guide

Based on the Cloudflare interface you're looking at:

**Permissions Section:**
```
Zone → DNS → Edit
[+ Add more] → Zone → Zone → Read (optional)
```

**Zone Resources:**
```
Include → All zones
OR
Include → Specific zone → [Select your domain]
```

**Client IP Address Filtering:**
```
Operator: is in
Value: your_server_ip_address
```

This configuration will allow PhishHawk to:
- ✅ Pause DNS zones (stops domain resolution)
- ✅ Check domain registration
- ✅ Lock domains (if registrar API available)

