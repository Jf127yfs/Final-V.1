# 🔒 SECURITY AUDIT REPORT
## Panopticon Analytics - Final-V.1
**Date:** October 23, 2025
**Branch:** Help
**Auditor:** Claude Code Security Review

---

## 📋 EXECUTIVE SUMMARY

This security audit reviews the Panopticon Analytics system for vulnerabilities, data exposure risks, and security best practices. The system processes sensitive guest data including birthdates, ZIP codes, gender identity, photos, and personal preferences.

**Overall Risk Level:** 🟡 **MEDIUM**

**Critical Issues Found:** 2
**High Priority Issues:** 5
**Medium Priority Issues:** 8
**Low Priority Issues:** 3

---

## 🔴 CRITICAL ISSUES

### 1. Hardcoded Google Drive Folder ID
**Location:** `Code:398`, `Check1:238`
**Risk:** High - Exposes internal infrastructure

**Finding:**
```javascript
const folderId = '1ZcP5jpYsYy0xuGqlFYNrDgG4K40eEKJB';
```

**Impact:**
- Folder ID is publicly visible in repository
- Anyone can potentially access the folder if permissions are misconfigured
- Makes it easy for attackers to target specific resources

**Recommendation:**
```javascript
// Use Script Properties instead
const folderId = PropertiesService.getScriptProperties().getProperty('PHOTOS_FOLDER_ID');
if (!folderId) {
  throw new Error('PHOTOS_FOLDER_ID not configured');
}
```

**Priority:** 🔴 CRITICAL - Fix immediately

---

### 2. No Rate Limiting on Check-In Endpoint
**Location:** `Code:163` - `checkInGuest()` function
**Risk:** High - Brute force vulnerability

**Finding:**
- Check-in accepts ZIP code, gender, and birthday for authentication
- No rate limiting or attempt tracking
- Attacker could enumerate valid guest combinations

**Attack Scenario:**
```
1. Attacker knows event ZIP code (64110)
2. Gender has only 4 options (man/woman/nonbinary/other)
3. Birthday is 365 possible days
4. Total combinations: 1 × 4 × 365 = 1,460 attempts
5. Could brute force all valid guests in minutes
```

**Recommendation:**
- Implement rate limiting (max 5 attempts per IP per hour)
- Add CAPTCHA after 3 failed attempts
- Log failed attempt patterns
- Consider adding email verification

**Priority:** 🔴 CRITICAL - Fix before event

---

## 🟠 HIGH PRIORITY ISSUES

### 3. XSS Vulnerability in Error Messages
**Location:** `wall:209`, `wall:202`, `MapDisplay:726`
**Risk:** Medium-High - Stored XSS possible

**Finding:**
```javascript
document.getElementById('loading').innerHTML =
  '<div>❌ ERROR LOADING DATA<br>' + error.message + '</div>';
```

**Impact:**
- If `error.message` contains user-controlled data, XSS is possible
- Could execute malicious JavaScript in user browsers
- Affects multiple HTML files (wall, MapDisplay, Intro)

**Recommendation:**
```javascript
// Use textContent instead of innerHTML
const loadingDiv = document.getElementById('loading');
loadingDiv.textContent = 'ERROR LOADING DATA: ' + error.message;

// OR sanitize first
function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
document.getElementById('loading').innerHTML =
  '<div>ERROR: ' + escapeHtml(error.message) + '</div>';
```

**Priority:** 🟠 HIGH - Fix before event

---

### 4. Sensitive Data in Logger.log() Statements
**Location:** `Code:165`, `Code:203`, `Code:238`
**Risk:** Medium - Information disclosure

**Finding:**
```javascript
Logger.log('Payload received: ' + JSON.stringify(payload));
Logger.log(`Searching for: ZIP="${zipCode}", Gender="${gender}", Birthday="${normalizedBirthday}"`);
Logger.log(`✓ Guest found at row ${i+1}: ${rowScreenName} (${rowUID})`);
```

**Impact:**
- Logs contain PII (birthdates, ZIP codes, UIDs)
- Logs are visible to all script editors
- Could be exposed if project is shared
- Violates data minimization principle

**Recommendation:**
```javascript
// Use development-only logging
const DEBUG_MODE = false; // Set via Script Properties

function debugLog(message) {
  if (DEBUG_MODE) {
    Logger.log('[DEBUG] ' + message);
  }
}

// Redact sensitive data
Logger.log(`Check-in attempt: ZIP=${zipCode.substring(0,3)}**, Gender=${gender}, DOB=**/**`);
```

**Priority:** 🟠 HIGH - Fix before production

---

### 5. No Input Validation Length Limits
**Location:** `Code:169-171`
**Risk:** Medium - DoS vulnerability

**Finding:**
```javascript
const zipCode = String(payload.zip || '').trim();
const gender = String(payload.gender || '').trim();
const birthday = String(payload.dob || '').trim();
```

**Impact:**
- No maximum length checks
- Could send very large strings causing memory issues
- Potential denial of service

**Recommendation:**
```javascript
const MAX_INPUT_LENGTH = 100;

function validateInput(input, fieldName, maxLength = MAX_INPUT_LENGTH) {
  const cleaned = String(input || '').trim();
  if (cleaned.length > maxLength) {
    throw new Error(`${fieldName} exceeds maximum length of ${maxLength}`);
  }
  return cleaned;
}

const zipCode = validateInput(payload.zip, 'ZIP code', 5);
const gender = validateInput(payload.gender, 'Gender', 20);
const birthday = validateInput(payload.dob, 'Birthday', 10);
```

**Priority:** 🟠 HIGH - Fix soon

---

### 6. Photo Upload Without File Type Validation
**Location:** `Code:417-419`
**Risk:** Medium - Malicious file upload

**Finding:**
```javascript
const decodedData = Utilities.base64Decode(base64Data);
const blob = Utilities.newBlob(decodedData, mimeType, uniqueFileName);
const file = folder.createFile(blob);
```

**Impact:**
- Accepts any mimeType without validation
- Could upload executable files, scripts, etc.
- No file size limit check

**Recommendation:**
```javascript
// Whitelist allowed MIME types
const ALLOWED_MIME_TYPES = [
  'image/jpeg',
  'image/jpg',
  'image/png',
  'image/gif',
  'image/webp'
];

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

function validatePhotoUpload(mimeType, base64Data) {
  if (!ALLOWED_MIME_TYPES.includes(mimeType.toLowerCase())) {
    throw new Error('Invalid file type. Only images allowed (JPEG, PNG, GIF, WebP)');
  }

  const fileSize = base64Data.length * 0.75; // Approximate size
  if (fileSize > MAX_FILE_SIZE) {
    throw new Error('File too large. Maximum 5MB allowed');
  }
}

validatePhotoUpload(mimeType, base64Data);
```

**Priority:** 🟠 HIGH - Fix before event

---

### 7. Screen Name Update Without Authorization
**Location:** `Code:300-361`
**Risk:** Medium - Unauthorized data modification

**Finding:**
```javascript
function updateGuestScreenName(payload) {
  const uid = String(payload.uid || '').trim();
  const newScreenName = String(payload.newScreenName || '').trim();
  // ... updates screen name without verifying caller owns this UID
}
```

**Impact:**
- Any user can change any guest's screen name if they know the UID
- UIDs are visible in wall visualization
- Could lead to impersonation or harassment

**Recommendation:**
```javascript
// Option 1: Require session token
function updateGuestScreenName(payload) {
  const uid = payload.uid;
  const newScreenName = payload.newScreenName;
  const sessionToken = payload.sessionToken;

  // Verify session token matches UID
  if (!verifySession(uid, sessionToken)) {
    throw new Error('Unauthorized: Invalid session');
  }
  // ... proceed with update
}

// Option 2: Require re-authentication
function updateGuestScreenName(payload) {
  const uid = payload.uid;
  const zipCode = payload.zip;
  const birthday = payload.dob;

  // Re-verify identity before allowing update
  if (!verifyGuestIdentity(uid, zipCode, birthday)) {
    throw new Error('Unauthorized: Identity verification failed');
  }
  // ... proceed with update
}
```

**Priority:** 🟠 HIGH - Fix before event

---

## 🟡 MEDIUM PRIORITY ISSUES

### 8. Insufficient Screen Name Validation
**Location:** `Code:316-319`
**Risk:** Low-Medium - XSS in displays

**Finding:**
```javascript
if (newScreenName.length < 3 || newScreenName.length > 50) {
  return {
    ok: false,
    message: 'Screen name must be 3-50 characters long'
  };
}
```

**Impact:**
- No character validation (could contain HTML, scripts, emoji)
- Could break visualizations or cause XSS
- No profanity/hate speech filter

**Recommendation:**
```javascript
function validateScreenName(name) {
  // Length check
  if (name.length < 3 || name.length > 50) {
    throw new Error('Screen name must be 3-50 characters');
  }

  // Allowed characters only (alphanumeric, spaces, basic punctuation)
  if (!/^[a-zA-Z0-9\s\-_\.]+$/.test(name)) {
    throw new Error('Screen name contains invalid characters');
  }

  // No HTML tags
  if (/<[^>]*>/g.test(name)) {
    throw new Error('HTML tags not allowed in screen name');
  }

  // No excessive spaces
  if (/\s{3,}/.test(name)) {
    throw new Error('Excessive spaces not allowed');
  }

  return name.trim();
}
```

**Priority:** 🟡 MEDIUM - Fix before production

---

### 9. Error Messages Leak System Information
**Location:** `Code:186`, `Code:292`
**Risk:** Low - Information disclosure

**Finding:**
```javascript
return {
  ok: false,
  message: 'System error: Data sheet not found. Please contact support.'
};
```

**Impact:**
- Reveals internal system structure ("Data sheet")
- Helps attackers understand system architecture
- Different errors for different failures aids enumeration

**Recommendation:**
```javascript
// Generic error messages for users
return {
  ok: false,
  message: 'Unable to complete check-in. Please try again or contact support.',
  errorCode: 'CHECKIN_001' // Use error codes for support debugging
};

// Log detailed errors server-side only
Logger.log('ERROR CHECKIN_001: Data sheet not found');
```

**Priority:** 🟡 MEDIUM - Fix soon

---

### 10. No HTTPS Enforcement
**Location:** All web app deployments
**Risk:** Medium - Man-in-the-middle attacks

**Finding:**
- Google Apps Script web apps support both HTTP and HTTPS
- No explicit HTTPS enforcement in code
- Sensitive data transmitted (birthdates, photos)

**Recommendation:**
```javascript
// Add to doGet() function
function doGet(e) {
  // Check if HTTPS
  const url = ScriptApp.getService().getUrl();
  if (!url.startsWith('https://')) {
    return HtmlService.createHtmlOutput(
      '<h1>HTTPS Required</h1><p>Please access via HTTPS</p>'
    );
  }
  // ... rest of code
}
```

**Priority:** 🟡 MEDIUM - Fix before event

---

### 11. Birthday Format Validation Too Permissive
**Location:** `Code:194-201`
**Risk:** Low-Medium - Logic errors

**Finding:**
```javascript
const birthdayParts = birthday.split('/');
if (birthdayParts.length >= 2) {
  const month = parseInt(birthdayParts[0], 10);
  const day = parseInt(birthdayParts[1], 10);
  // ... no validation that month is 1-12, day is 1-31
}
```

**Impact:**
- Accepts invalid dates (99/99, 00/00, 13/45)
- Could lead to matching errors
- Confusing UX

**Recommendation:**
```javascript
function validateBirthday(birthday) {
  const parts = birthday.split('/');
  if (parts.length !== 2) {
    throw new Error('Birthday must be in MM/DD format');
  }

  const month = parseInt(parts[0], 10);
  const day = parseInt(parts[1], 10);

  if (month < 1 || month > 12) {
    throw new Error('Invalid month. Must be 1-12');
  }

  if (day < 1 || day > 31) {
    throw new Error('Invalid day. Must be 1-31');
  }

  // Check for valid day in month
  const daysInMonth = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day > daysInMonth[month - 1]) {
    throw new Error(`Invalid day for month ${month}`);
  }

  return String(month).padStart(2, '0') + '/' + String(day).padStart(2, '0');
}
```

**Priority:** 🟡 MEDIUM - Fix soon

---

### 12. No Content Security Policy (CSP)
**Location:** All HTML files
**Risk:** Medium - XSS mitigation missing

**Finding:**
- No CSP meta tags in HTML files
- Could prevent many XSS attacks
- Industry best practice

**Recommendation:**
Add to all HTML file `<head>` sections:
```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self';
               script-src 'self' 'unsafe-inline' https://maps.googleapis.com https://unpkg.com;
               style-src 'self' 'unsafe-inline' https://unpkg.com;
               img-src 'self' data: https:;
               connect-src 'self' https://script.google.com;">
```

**Priority:** 🟡 MEDIUM - Implement when possible

---

### 13. Guest Data Returned to Frontend
**Location:** `Code:271-279`
**Risk:** Low-Medium - Data exposure

**Finding:**
```javascript
return {
  ok: true,
  message: 'Check-in successful!',
  screenName: rowScreenName,
  uid: rowUID,
  photoUrl: data[i][29] || ''
};
```

**Impact:**
- Returns UID to client (could be used for unauthorized updates)
- Photo URL reveals Drive structure
- More data than necessary for UX

**Recommendation:**
```javascript
// Return only what's needed for UI
return {
  ok: true,
  message: 'Check-in successful!',
  screenName: rowScreenName,
  // Don't return UID to client
  // Use session token instead for subsequent requests
  sessionToken: generateSessionToken(rowUID)
};
```

**Priority:** 🟡 MEDIUM - Improve security posture

---

### 14. No Audit Trail for Data Changes
**Location:** All update functions
**Risk:** Low - Forensics/compliance

**Finding:**
- No logging of who changed what data
- No timestamp tracking for updates
- Difficult to investigate issues or abuse

**Recommendation:**
```javascript
// Create audit log sheet
function logAuditEvent(action, uid, field, oldValue, newValue) {
  const auditSheet = SpreadsheetApp.getActiveSpreadsheet()
    .getSheetByName('Audit_Log') || createAuditSheet();

  auditSheet.appendRow([
    new Date(),
    action,
    uid,
    field,
    oldValue,
    newValue,
    Session.getActiveUser().getEmail() // If available
  ]);
}

// Call in update functions
logAuditEvent('SCREEN_NAME_UPDATE', uid, 'Screen Name', oldName, newName);
```

**Priority:** 🟡 MEDIUM - Good practice

---

### 15. Potential Timing Attack in Guest Lookup
**Location:** `Code:206-281`
**Risk:** Low - Guest enumeration

**Finding:**
```javascript
for (let i = 1; i < data.length; i++) {
  // ... searches linearly through all guests
  if (match) {
    return success;
  }
}
return failure;
```

**Impact:**
- Response time varies based on guest position in sheet
- Attacker could determine valid vs invalid guests by timing
- Very difficult to exploit in practice

**Recommendation:**
```javascript
// Add consistent delay regardless of result
function checkInGuest(payload) {
  const startTime = Date.now();

  // ... perform check-in logic
  const result = performCheckIn(payload);

  // Ensure minimum response time (prevent timing attacks)
  const elapsed = Date.now() - startTime;
  const MIN_RESPONSE_TIME = 500; // 500ms
  if (elapsed < MIN_RESPONSE_TIME) {
    Utilities.sleep(MIN_RESPONSE_TIME - elapsed);
  }

  return result;
}
```

**Priority:** 🟢 LOW - Nice to have

---

## 🟢 LOW PRIORITY ISSUES

### 16. Missing Input Trimming Consistency
**Location:** Various
**Risk:** Very Low - Minor data quality issues

**Finding:**
- Some inputs are trimmed, others are not
- Inconsistent handling of whitespace
- Could lead to matching failures

**Recommendation:**
Standardize all input handling with a utility function.

**Priority:** 🟢 LOW

---

### 17. No Backup/Recovery Mechanism
**Location:** All sheets
**Risk:** Low - Data loss

**Finding:**
- No automatic backups of guest data
- Sheet corruption could lose all data
- No disaster recovery plan

**Recommendation:**
```javascript
// Daily backup trigger
function backupData() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const backupName = 'Backup_' + new Date().toISOString().split('T')[0];
  ss.copy(backupName);
}

// Set up daily trigger
ScriptApp.newTrigger('backupData')
  .timeBased()
  .atHour(3)
  .everyDays(1)
  .create();
```

**Priority:** 🟢 LOW - Good practice

---

### 18. Comments Contain Placeholder Text
**Location:** Various
**Risk:** Very Low - Code quality

**Finding:**
```javascript
function getOrCreatePhotosFolder_() {
  // Check if Photos folder exists in Drive root
  // If not found: create new folder with appropriate name
  // ... but actual implementation is missing
}
```

**Recommendation:**
Complete implementation or remove placeholder functions.

**Priority:** 🟢 LOW - Code cleanup

---

## 🛡️ SECURITY BEST PRACTICES RECOMMENDATIONS

### Authentication & Authorization
1. ✅ Implement session management with tokens
2. ✅ Add rate limiting to all public endpoints
3. ✅ Require re-authentication for sensitive operations
4. ✅ Use OAuth for admin access (not built-in auth)

### Data Protection
1. ✅ Move secrets to Script Properties
2. ✅ Implement data encryption at rest (if possible)
3. ✅ Minimize PII in logs
4. ✅ Implement data retention policies

### Input Validation
1. ✅ Validate all inputs (type, length, format)
2. ✅ Sanitize before storing in sheets
3. ✅ Escape before rendering in HTML
4. ✅ Use allowlists instead of denylists

### Infrastructure
1. ✅ Enforce HTTPS only
2. ✅ Implement CSP headers
3. ✅ Regular security audits
4. ✅ Penetration testing before launch

### Monitoring & Response
1. ✅ Log all authentication attempts
2. ✅ Alert on suspicious patterns
3. ✅ Incident response plan
4. ✅ Regular backup verification

---

## 📊 RISK MATRIX

| Issue | Severity | Likelihood | Risk Score | Priority |
|-------|----------|------------|------------|----------|
| Hardcoded Folder ID | High | Medium | 🔴 Critical | 1 |
| No Rate Limiting | High | High | 🔴 Critical | 1 |
| XSS in Error Messages | Medium | Medium | 🟠 High | 2 |
| PII in Logs | Medium | High | 🟠 High | 2 |
| No Length Limits | Medium | Low | 🟠 High | 3 |
| File Upload Validation | High | Low | 🟠 High | 3 |
| Unauthorized Updates | Medium | Medium | 🟠 High | 3 |
| Screen Name Validation | Low | Medium | 🟡 Medium | 4 |
| Error Info Disclosure | Low | Medium | 🟡 Medium | 4 |
| No HTTPS Enforcement | Medium | Low | 🟡 Medium | 4 |
| Birthday Validation | Low | Medium | 🟡 Medium | 5 |
| No CSP | Medium | Low | 🟡 Medium | 5 |
| Data Exposure | Low | Medium | 🟡 Medium | 5 |
| No Audit Trail | Low | Low | 🟡 Medium | 6 |
| Timing Attack | Very Low | Very Low | 🟢 Low | 7 |

---

## ✅ IMMEDIATE ACTION ITEMS

### Before Event Launch (Critical Path):

1. **Fix Hardcoded Secrets** (2 hours)
   - Move folder ID to Script Properties
   - Update Code.gs and Check1.gs

2. **Implement Rate Limiting** (4 hours)
   - Add attempt tracking
   - Implement cooldown periods
   - Add CAPTCHA integration

3. **Fix XSS Vulnerabilities** (3 hours)
   - Replace innerHTML with textContent
   - Add input sanitization function
   - Update all HTML files

4. **Reduce PII in Logs** (2 hours)
   - Add debug mode flag
   - Redact sensitive data in logs
   - Update logging statements

5. **Add File Upload Validation** (2 hours)
   - Whitelist MIME types
   - Add file size checks
   - Implement validation function

6. **Secure Screen Name Updates** (3 hours)
   - Add authorization check
   - Require re-authentication
   - Implement session tokens

**Total Estimated Time:** 16 hours

---

## 📝 COMPLIANCE NOTES

### Data Privacy Considerations:
- ✅ Guest data includes PII (birthdates, photos, location)
- ✅ May be subject to GDPR if EU guests attend
- ✅ May be subject to CCPA if California guests attend
- ⚠️ No privacy policy visible in codebase
- ⚠️ No data retention policy defined
- ⚠️ No guest consent mechanism

### Recommendations:
1. Add privacy policy page
2. Implement consent checkbox at check-in
3. Define data retention period
4. Add data deletion mechanism
5. Document data processing activities

---

## 🎯 CONCLUSION

The Panopticon Analytics system has **solid functionality** but requires **security hardening** before production use. The most critical issues are:

1. **Lack of rate limiting** (enables brute force attacks)
2. **Hardcoded secrets** (exposes infrastructure)
3. **XSS vulnerabilities** (could compromise user sessions)

With the recommended fixes implemented, the system will be significantly more secure and ready for production use.

**Estimated Total Remediation Time:** 25-30 hours
**Recommended Security Budget:** $3,000-5,000 for external penetration test

---

**Report Generated:** October 23, 2025
**Next Review:** After implementing fixes
**Contact:** security@panopticon-analytics.local
