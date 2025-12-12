# Bug Fixes Documentation

This document tracks all bug fixes implemented for the SecureBank application, organized by issue category.

---

## UI Issues

### UI-101: Dark Mode Text Visibility

**Priority:** Medium  
**Reporter:** Sarah Chen  
**File:** `app/globals.css`

#### What Caused the Bug

When dark mode is enabled (via system preferences), the CSS sets the body text color to light (`#ededed`). However, form input elements retain white backgrounds, causing the inherited light text color to be invisible against the white input background.

**Root Cause:**

```css
@media (prefers-color-scheme: dark) {
  :root {
    --foreground: #ededed; /* Light text for dark mode */
  }
}

body {
  color: var(--foreground); /* Inputs inherit this light color */
}
```

Input elements inherit the light foreground color but have white backgrounds, making text invisible.

#### How the Fix Resolves It

Added explicit text color styles for form elements in `globals.css`:

**Fixed Code:**

```css
/* Fix for UI-101: Ensure input text is visible in dark mode */
input,
textarea,
select {
  color: #171717; /* Dark text on light input backgrounds */
}

input::placeholder,
textarea::placeholder {
  color: #6b7280; /* Gray placeholder text */
}
```

This ensures:
- Input text is always dark (visible on white backgrounds)
- Placeholder text is gray and visible
- Works regardless of system color scheme

#### Preventative Measures

1. **Explicit Form Styling**: Always explicitly set text colors for form elements rather than relying on inheritance.

2. **Test Both Color Schemes**: Include dark mode testing in QA processes.

3. **Use CSS Variables Consistently**: If using CSS variables for theming, ensure form elements also use appropriate variables.

---

## Security Issues

### SEC-301: SSN Storage in Plaintext

**Priority:** Critical  
**Reporter:** Security Audit Team  
**File:** `server/routers/auth.ts`

#### What Caused the Bug

The SSN (Social Security Number) was being stored in plaintext in the database during user signup. The issue occurred because the code was using the spread operator (`...input`) to insert all input fields directly into the database, including the SSN, without applying any hashing.

**Vulnerable Code (lines 39-42):**

```typescript
const hashedPassword = await bcrypt.hash(input.password, 10);

await db.insert(users).values({
  ...input,
  password: hashedPassword,
});
```

The `...input` spread operator included the `ssn` field in plaintext, while only the `password` was being hashed before insertion. This created a severe privacy and compliance risk, as SSNs are sensitive personally identifiable information (PII) that must be protected.

#### How to Reproduce the Bug

The bug can be verified by checking the database contents before and after the fix:

1. **Before the fix:**
   - Created a test user with email `test@test.com` and SSN `999999999` through the signup flow
   - Ran `npm run db:list-users` to inspect the database
   - **Output:**
     ```
     ID: 1, Email: test@test.com, Name: Test Test, SSN: 999999999
     ```
   - The SSN is visible in plaintext, confirming the vulnerability

2. **After the fix:**
   - Created a new user with email `sec301@test.com` and SSN `999999999` through the signup flow
   - Ran `npm run db:list-users` to inspect the database
   - **Output:**
     ```
     ID: 1, Email: test@test.com, Name: Test Test, SSN: 999999999
     ID: 2, Email: sec301@test.com, Name: Sec 301, SSN: $2b$10$HzBaHOniK.lQVigoEUTVAOGUmrOegODDrHFHQc2pTaXhQWnHUsFWK
     ```
   - The SSN is now stored as a bcrypt hash, confirming the fix is working correctly

#### How the Fix Resolves It

The fix hashes the SSN using `bcrypt` (the same secure hashing algorithm used for passwords) before storing it in the database. The SSN is now hashed with a salt round of 10, making it computationally infeasible to reverse the hash and recover the original SSN value.

**Fixed Code (lines 39-44):**

```typescript
const hashedPassword = await bcrypt.hash(input.password, 10);
const hashedSSN = await bcrypt.hash(input.ssn, 10);

await db.insert(users).values({
  ...input,
  password: hashedPassword,
  ssn: hashedSSN,
});
```

By explicitly hashing the SSN and overriding it in the insert statement, we ensure that only the hashed version is stored in the database, protecting user privacy and meeting compliance requirements.

**Additional Fix - Don't return SSN in API responses (lines 77, 125):**

The original code returned the user object with only the password removed:

```typescript
return { user: { ...user, password: undefined }, token };
```

This still exposed the SSN (even if hashed) in API responses. The fix removes the SSN from all API responses:

```typescript
// Fix for SEC-301: Don't return sensitive data (password, SSN) in API response
return { user: { ...user, password: undefined, ssn: undefined }, token };
```

Sensitive data like SSN should never be returned in API responses, even when hashed.

#### Preventative Measures

To avoid similar issues in the future:

1. **Security Review Checklist**: Create a security review checklist that includes verifying all sensitive PII fields (SSN, credit card numbers, bank account numbers, etc.) are properly hashed or encrypted before database insertion.


3. **Code Review Guidelines**: Establish code review guidelines that require explicit review of any database insert operations involving PII or sensitive data.

4. **Automated Security Scanning**: Implement automated security scanning tools (e.g., static analysis tools, linters) that can detect plaintext storage of known sensitive data patterns.

5. **Avoid Spread Operators for Sensitive Data**: When inserting sensitive fields, explicitly list each field rather than using spread operators, or create a utility function that automatically hashes sensitive fields before insertion.

6. **Database Schema Documentation**: Document which fields in the database schema contain sensitive data and require hashing/encryption, making it clear to developers during implementation.

---

### SEC-302: Insecure Random Numbers

**Priority:** High  
**Reporter:** Security Team  
**File:** `server/routers/account.ts`

#### What Caused the Bug

The `generateAccountNumber()` function used `Math.random()` to generate account numbers. `Math.random()` is a pseudo-random number generator (PRNG) that is not cryptographically secure. It uses a predictable algorithm seeded with a value that can potentially be guessed or observed, making the generated account numbers potentially predictable by attackers.

**Vulnerable Code (lines 8-12):**

```typescript
function generateAccountNumber(): string {
  return Math.floor(Math.random() * 1000000000)
    .toString()
    .padStart(10, "0");
}
```

This creates a security risk where:
- An attacker could potentially predict future account numbers
- Account enumeration attacks become easier
- Sensitive financial accounts could be targeted

#### How the Fix Resolves It

The fix replaces `Math.random()` with Node.js's `crypto.randomInt()`, which provides cryptographically secure random number generation. This uses the operating system's cryptographically secure random number generator, making the output unpredictable.

**Fixed Code (lines 8-11):**

```typescript
import { randomInt } from "crypto";

// Fix for SEC-302: Use cryptographically secure random number generator
function generateAccountNumber(): string {
  return randomInt(0, 1000000000).toString().padStart(10, "0");
}
```

This ensures:
- Account numbers are generated using cryptographically secure randomness
- The output is unpredictable and cannot be guessed by attackers
- Compliance with security best practices for financial applications

#### Preventative Measures

To avoid similar issues in the future:

1. **Ban Math.random() for Security Operations**: Establish a coding standard that prohibits `Math.random()` for any security-sensitive operations (IDs, tokens, account numbers, etc.).

2. **Linting Rules**: Add ESLint rules or custom linters to flag `Math.random()` usage and suggest `crypto` alternatives.

3. **Security Code Review Checklist**: Include random number generation as a specific item in security code reviews.

4. **Use Established Libraries**: Consider using well-vetted libraries like `uuid` or `nanoid` for generating unique identifiers.

5. **Documentation**: Document which types of identifiers require cryptographic randomness vs. simple uniqueness.

---

### SEC-303: XSS Vulnerability

**Priority:** Critical  
**Reporter:** Security Audit  
**File:** `components/TransactionList.tsx`

#### What Caused the Bug

The transaction list component used `dangerouslySetInnerHTML` to render transaction descriptions, which allows arbitrary HTML (including malicious JavaScript) to be injected and executed in the user's browser.

**Vulnerable Code (line 71):**

```tsx
{transaction.description ? <span dangerouslySetInnerHTML={{ __html: transaction.description }} /> : "-"}
```

This creates a Cross-Site Scripting (XSS) vulnerability where:
- An attacker could inject malicious scripts via transaction descriptions
- The script would execute in victims' browsers when viewing their transaction history
- Attackers could steal session tokens, perform actions on behalf of users, or redirect to phishing sites

#### How the Fix Resolves It

The fix removes `dangerouslySetInnerHTML` and renders the description as plain text. React automatically escapes text content, preventing any HTML or JavaScript from being executed.

**Fixed Code (line 71):**

```tsx
{transaction.description ? <span>{transaction.description}</span> : "-"}
```

This ensures:
- All transaction descriptions are rendered as plain text
- Any HTML tags or JavaScript in the description are displayed as literal text, not executed
- Users are protected from XSS attacks

#### Preventative Measures

To avoid similar issues in the future:

1. **Never Use dangerouslySetInnerHTML**: Avoid `dangerouslySetInnerHTML` unless absolutely necessary. If it must be used, always sanitize the HTML using a library like DOMPurify.

2. **ESLint Rules**: Add ESLint rules to flag `dangerouslySetInnerHTML` usage:
   ```json
   "react/no-danger": "error"
   ```

3. **Input Sanitization**: Sanitize user input on the server side before storing it in the database.

4. **Content Security Policy (CSP)**: Implement CSP headers to mitigate the impact of XSS attacks.

5. **Security Code Reviews**: Include XSS vulnerability checks in code review checklists, especially for any code that renders user-generated content.

6. **Automated Security Scanning**: Use security scanning tools that detect potential XSS vulnerabilities in React code.

---

### SEC-304: Session Management

**Priority:** High  
**Reporter:** DevOps Team  
**Files:** `server/routers/auth.ts`, `lib/trpc/Provider.tsx`

#### What Caused the Bug

The session management had two critical issues:

1. **Multiple valid sessions per user**: Each login created a new session without invalidating existing ones
2. **No session invalidation**: Old sessions remained valid until expiry, even after new logins

**Vulnerable Code (login mutation):**

```typescript
await db.insert(sessions).values({
  userId: user.id,
  token,
  expiresAt: expiresAt.toISOString(),
});
```

This allowed unlimited concurrent sessions per user. If credentials were compromised, an attacker could maintain access even after the user logged in again or "logged out" (which only deleted the current session).

#### How the Fix Resolves It

Implemented a **single session policy** - when a user logs in or signs up, all existing sessions are invalidated before creating a new one:

**Fixed Code:**

```typescript
// Fix for SEC-304: Invalidate all existing sessions before creating new one (single session policy)
await db.delete(sessions).where(eq(sessions.userId, user.id));

await db.insert(sessions).values({
  userId: user.id,
  token,
  expiresAt: expiresAt.toISOString(),
});
```

This ensures:
- Only one active session per user at any time
- Logging in from a new device automatically logs out from all other devices
- If credentials are compromised, user can regain exclusive access by logging in again

**Frontend Fix (lib/trpc/Provider.tsx):**

Added global error handling to redirect users to login when their session becomes invalid:

```typescript
fetch(url, options).then(async (response) => {
  // Check for 401 and redirect to login
  if (response.status === 401 && typeof window !== "undefined") {
    const cloned = response.clone();
    const data = await cloned.json().catch(() => null);
    if (data?.error?.data?.code === "UNAUTHORIZED" || data?.[0]?.error?.data?.code === "UNAUTHORIZED") {
      window.location.href = "/login";
    }
  }
  return response;
});
```

This ensures users are redirected to login when their session is invalidated (e.g., by logging in from another device).

#### Preventative Measures

1. **Single Session Policy for Banking Apps**: Financial applications should enforce one session per user for maximum security.

2. **Session Audit Logging**: Log session creation/deletion events for security monitoring.

3. **Automatic Session Cleanup**: Implement a background job to clean up expired sessions from the database.

---

## Validation Issues

### VAL-201: Email Validation Problems

**Priority:** High  
**Reporter:** James Wilson  
**Files:** `server/routers/auth.ts`, `app/signup/page.tsx`

#### What Caused the Bug

The email validation had two issues:
1. Basic regex pattern that didn't validate top-level domains
2. Accepted any domain extension, including typos and invalid TLDs

**Vulnerable Code (Backend):**

```typescript
email: z.string().email().toLowerCase(),
```

**Vulnerable Code (Frontend):**

```typescript
pattern: {
  value: /^\S+@\S+$/i,
  message: "Invalid email address",
},
```

This accepted emails with invalid domains like "user@gmail.con" or "user@test.xyz123".

#### How the Fix Resolves It

Added validation to check for valid top-level domains (whitelist approach):

**Fixed Code (Backend):**

```typescript
email: z.string()
  .email("Invalid email address")
  .toLowerCase()
  .refine((email) => {
    const validTLDs = [".com", ".org", ".net", ".edu", ".gov", ".mil", ".co", ".io", ".dev", ".app", ".me", ".info", ".biz", ".us", ".uk", ".ca", ".au", ...];
    return validTLDs.some(tld => email.endsWith(tld));
  }, "Please use a valid email domain (e.g., .com, .org, .edu)"),
```

**Fixed Code (Frontend):**

```typescript
validate: {
  validTLD: (value) => {
    const validTLDs = [".com", ".org", ".net", ".edu", ".gov", ".mil", ".co", ".io", ".dev", ".app", ".me", ".info", ".biz", ".us", ".uk", ".ca", ".au", ...];
    const hasValidTLD = validTLDs.some(tld => value.toLowerCase().endsWith(tld));
    return hasValidTLD || "Please use a valid email domain (e.g., .com, .org, .edu)";
  },
},
```

The whitelist includes common TLDs: .com, .org, .net, .edu, .gov, .mil, .co, .io, .dev, .app, .me, .info, .biz, and many country-code TLDs.

#### Preventative Measures

1. **Comprehensive Email Validation**: Check for common typos in addition to format validation.

2. **User-Friendly Errors**: Provide helpful messages that suggest the user check for typos.

3. **Consider Email Verification**: For critical applications, send a verification email to confirm the address.

---

### VAL-203: State Code Validation

**Priority:** Medium  
**Reporter:** Alex Thompson  
**Files:** `server/routers/auth.ts`, `app/signup/page.tsx`

#### What Caused the Bug

The state validation only checked for 2 uppercase characters, without validating that it's an actual US state code:

**Vulnerable Code (Backend):**

```typescript
state: z.string().length(2).toUpperCase(),
```

**Vulnerable Code (Frontend):**

```typescript
pattern: {
  value: /^[A-Z]{2}$/,
  message: "Use 2-letter state code",
},
```

This accepted any 2-letter combination like "XX", "ZZ", or "AB", which are not valid US state codes.

#### How the Fix Resolves It

Added validation against a list of valid US state codes:

**Fixed Code (Backend):**

```typescript
state: z.string().length(2).toUpperCase().refine((val) => {
  const validStates = ["AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY", "DC", "PR", "VI", "GU", "AS", "MP"];
  return validStates.includes(val);
}, "Invalid US state code"),
```

**Fixed Code (Frontend):**

```typescript
validate: {
  validState: (value) => {
    const validStates = ["AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY", "DC", "PR", "VI", "GU", "AS", "MP"];
    return validStates.includes(value.toUpperCase()) || "Invalid US state code";
  },
},
```

The list includes all 50 US states plus DC, Puerto Rico, Virgin Islands, Guam, American Samoa, and Northern Mariana Islands.

#### Preventative Measures

1. **Use Allowlists for Fixed Values**: For fields with a known set of valid values, use an allowlist rather than pattern matching.


---

### VAL-202: Date of Birth Validation

**Priority:** Critical  
**Reporter:** Maria Garcia  
**File:** `server/routers/auth.ts` and `app/signup/page.tsx`

#### What Caused the Bug

The date of birth validation only checked that the value was a string, without validating:
- The date format
- Whether the date is in the past
- Whether the user is at least 18 years old (required for banking)

**Vulnerable Code (line 19):**

```typescript
dateOfBirth: z.string(),
```

This allowed users to enter any string, including future dates like "2025-01-01", which creates compliance issues for a banking application.

#### How the Fix Resolves It

The fix adds comprehensive date validation using Zod's `refine()` method:

**Fixed Code:**

```typescript
// Fix for VAL-202: Validate date of birth
dateOfBirth: z.string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, "Invalid date format (YYYY-MM-DD)")
  .refine((date) => {
    const dob = new Date(date);
    return !isNaN(dob.getTime());
  }, "Invalid date")
  .refine((date) => {
    const dob = new Date(date);
    return dob <= new Date();
  }, "Date of birth cannot be in the future")
  .refine((date) => {
    const dob = new Date(date);
    const today = new Date();
    const age = today.getFullYear() - dob.getFullYear();
    const monthDiff = today.getMonth() - dob.getMonth();
    const dayDiff = today.getDate() - dob.getDate();
    const actualAge = monthDiff < 0 || (monthDiff === 0 && dayDiff < 0) ? age - 1 : age;
    return actualAge >= 18;
  }, "You must be at least 18 years old"),
```

This ensures:
- Date must be in YYYY-MM-DD format (HTML date input format)
- Date must be a valid date
- Date cannot be in the future
- User must be at least 18 years old

#### Frontend Validation

In addition to server-side validation, frontend validation was added to `app/signup/page.tsx` to provide immediate feedback and prevent users from proceeding through the form with invalid dates:

**Frontend Validation Code:**

```typescript
<input
  {...register("dateOfBirth", {
    required: "Date of birth is required",
    validate: {
      notFuture: (value) => {
        const dob = new Date(value);
        return dob <= new Date() || "Date of birth cannot be in the future";
      },
      isAdult: (value) => {
        const dob = new Date(value);
        const today = new Date();
        const age = today.getFullYear() - dob.getFullYear();
        const monthDiff = today.getMonth() - dob.getMonth();
        const dayDiff = today.getDate() - dob.getDate();
        const actualAge = monthDiff < 0 || (monthDiff === 0 && dayDiff < 0) ? age - 1 : age;
        return actualAge >= 18 || "You must be at least 18 years old";
      },
    },
  })}
  type="date"
/>
```

This provides:
- Immediate validation feedback before form submission
- Prevents users from proceeding to the next step with an invalid date of birth
- Better user experience by catching errors early

#### Preventative Measures

To avoid similar issues in the future:

1. **Comprehensive Input Validation**: Always validate all aspects of user input, not just format but also business rules.

2. **Age Verification for Financial Apps**: Banking and financial applications must verify users are of legal age.

3. **Server-Side Validation**: Never rely solely on frontend validation; always validate on the server.

4. **Use Zod's refine()**: For complex validation logic, use Zod's `refine()` or `superRefine()` methods.


---

### VAL-206: Card Number Validation

**Priority:** Critical  
**Reporter:** David Brown  
**Files:** `components/FundingModal.tsx`, `server/routers/account.ts`

#### What Caused the Bug

The card number validation was inadequate, only checking:
1. That the number was exactly 16 digits
2. That it started with "4" (Visa) or "5" (Mastercard)

**Vulnerable Code:**

```typescript
pattern: {
  value: fundingType === "card" ? /^\d{16}$/ : /^\d+$/,
  message: fundingType === "card" ? "Card number must be 16 digits" : "Invalid account number",
},
validate: {
  validCard: (value) => {
    if (fundingType !== "card") return true;
    return value.startsWith("4") || value.startsWith("5") || "Invalid card number";
  },
},
```

This accepted any 16-digit number starting with 4 or 5, such as `4000000000000000`, which is not a valid card.

#### How the Fix Resolves It

The fix implements the **Luhn algorithm**, which is the industry-standard checksum formula used to validate credit card numbers. This algorithm can detect:
- Typos in card numbers
- Randomly generated fake numbers
- Numbers that fail the mathematical checksum

**Fixed Code (Frontend - FundingModal.tsx):**

```typescript
// Luhn algorithm to validate credit card numbers
function isValidCardNumber(cardNumber: string): boolean {
  const sanitized = cardNumber.replace(/[\s-]/g, "");
  if (!/^\d+$/.test(sanitized)) return false;
  if (sanitized.length < 13 || sanitized.length > 19) return false;
  
  let sum = 0;
  let isEven = false;
  for (let i = sanitized.length - 1; i >= 0; i--) {
    let digit = parseInt(sanitized[i], 10);
    if (isEven) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    isEven = !isEven;
  }
  return sum % 10 === 0;
}

// Updated validation
validate: {
  validCard: (value) => {
    if (fundingType !== "card") return true;
    if (!isValidCardNumber(value)) {
      return "Invalid card number";
    }
    return true;
  },
},
```

**Fixed Code (Backend - server/routers/account.ts):**

```typescript
// Server-side validation in fundAccount mutation
if (input.fundingSource.type === "card") {
  if (!isValidCardNumber(input.fundingSource.accountNumber)) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: "Invalid card number",
    });
  }
}
```

The fix also:
- Accepts cards with 13-19 digits (supporting Visa 13-digit, Amex 15-digit, and standard 16-digit cards)
- Validates on both frontend (immediate feedback) and backend (security)

> **Note:** This fix also resolves **VAL-210: Card Type Detection**. The old code only accepted cards starting with "4" (Visa) or "5" (Mastercard), rejecting valid cards from American Express (34, 37), Discover (6011, 65), JCB, Diners Club, and others. The Luhn algorithm is card-type agnostic—it validates the mathematical checksum regardless of card network, so all valid cards are now accepted.

#### Preventative Measures

1. **Use Industry-Standard Algorithms**: For payment validation, always use established algorithms like Luhn rather than simple prefix/length checks.

2. **Defense in Depth**: Validate on both frontend (UX) and backend (security).

3. **Test with Known Valid/Invalid Numbers**: Use test card numbers from payment providers to verify validation logic.

4. **Support Multiple Card Types**: Different card networks have different formats (Visa, Mastercard, Amex, Discover).

---

### VAL-205: Zero Amount Funding

**Priority:** High  
**Reporter:** Lisa Johnson  
**File:** `components/FundingModal.tsx`

#### What Caused the Bug

The amount validation had two issues:
1. The minimum value was set to `0.0` instead of `0.01`
2. Using `min` validation on a text input compares strings, not numbers

**Vulnerable Code:**

```typescript
<input
  {...register("amount", {
    required: "Amount is required",
    pattern: {
      value: /^\d+\.?\d{0,2}$/,
      message: "Invalid amount format",
    },
    min: {
      value: 0.0,
      message: "Amount must be at least $0.01",
    },
    max: {
      value: 10000,
      message: "Amount cannot exceed $10,000",
    },
  })}
  type="text"
/>
```

This allowed users to submit $0.00 funding requests, creating unnecessary transaction records.

#### How the Fix Resolves It

The fix replaces `min`/`max` with custom `validate` functions that properly parse the value as a number:

**Fixed Code:**

```typescript
<input
  {...register("amount", {
    required: "Amount is required",
    pattern: {
      value: /^\d+\.?\d{0,2}$/,
      message: "Invalid amount format",
    },
    validate: {
      // Fix for VAL-205: Prevent zero amount funding
      minAmount: (value) => {
        const amount = parseFloat(value);
        return amount >= 0.01 || "Amount must be at least $0.01";
      },
      maxAmount: (value) => {
        const amount = parseFloat(value);
        return amount <= 10000 || "Amount cannot exceed $10,000";
      },
    },
  })}
  type="text"
/>
```

The backend already validates with `z.number().positive()` which rejects zero and negative amounts.

#### Preventative Measures

1. **Use Custom Validators for Numeric Text Inputs**: React Hook Form's `min`/`max` on text inputs compare strings, not numbers.

2. **Test Edge Cases**: Always test with 0, negative numbers, and boundary values.


---

### VAL-207: Routing Number Optional

**Priority:** High  
**Reporter:** Support Team  
**File:** `server/routers/account.ts`

#### What Caused the Bug

The backend schema defined the routing number as optional:

**Vulnerable Code:**

```typescript
fundingSource: z.object({
  type: z.enum(["card", "bank"]),
  accountNumber: z.string(),
  routingNumber: z.string().optional(),  // Optional - allows bank transfers without routing number
}),
```

While the frontend required routing numbers for bank transfers, the backend didn't enforce this, allowing malformed requests to bypass frontend validation.

#### How the Fix Resolves It

Updated the Zod schema to conditionally require routing numbers when the funding type is "bank":

**Fixed Code:**

```typescript
fundingSource: z.object({
  type: z.enum(["card", "bank"]),
  accountNumber: z.string(),
  routingNumber: z.string().optional(),
}).refine(
  (data) => data.type !== "bank" || (data.routingNumber && /^\d{9}$/.test(data.routingNumber)),
  { message: "Routing number is required for bank transfers and must be 9 digits" }
),
```

The `refine()` function validates that:
- If type is NOT "bank", validation passes (routing number not needed for cards)
- If type IS "bank", routing number must exist AND be exactly 9 digits

#### Preventative Measures

1. **Backend Must Mirror Frontend Validation**: Any required field on the frontend should also be validated on the backend.

2. **Conditional Validation**: When fields are conditionally required based on other field values, ensure both frontend and backend implement the same logic.

3. **Never Trust Client Input**: Backend should always validate as the source of truth, regardless of frontend validation.

---

### VAL-208: Weak Password Requirements

**Priority:** Critical  
**Reporter:** Security Team  
**Files:** `server/routers/auth.ts`, `app/signup/page.tsx`

#### What Caused the Bug

The password validation only checked for minimum length (8 characters), without enforcing complexity requirements.

**Vulnerable Code (Backend):**

```typescript
password: z.string().min(8),
```

**Vulnerable Code (Frontend):**

```typescript
validate: {
  notCommon: (value) => {
    const commonPasswords = ["password", "12345678", "qwerty"];
    return !commonPasswords.includes(value.toLowerCase()) || "Password is too common";
  },
  hasNumber: (value) => /\d/.test(value) || "Password must contain a number",
},
```

This allowed weak passwords like `aaaaaaaa` or `password1` which are easily guessable or vulnerable to brute-force attacks.

#### How the Fix Resolves It

The fix adds comprehensive password complexity requirements on both frontend and backend:

**Fixed Code (Backend - server/routers/auth.ts):**

```typescript
// Fix for VAL-208: Strong password requirements
password: z.string()
  .min(8, "Password must be at least 8 characters")
  .refine((val) => /[A-Z]/.test(val), "Password must contain at least one uppercase letter")
  .refine((val) => /[a-z]/.test(val), "Password must contain at least one lowercase letter")
  .refine((val) => /\d/.test(val), "Password must contain at least one number")
  .refine((val) => /[!@#$%^&*(),.?":{}|<>]/.test(val), "Password must contain at least one special character")
  .refine((val) => {
    const commonPatterns = ["password", "qwerty", "123456", "letmein", "welcome", "admin", "login"];
    const strippedValue = val.toLowerCase().replace(/[^a-z]/g, "");
    return !commonPatterns.some(pattern => strippedValue.includes(pattern));
  }, "Password contains a common pattern"),
```

**Fixed Code (Frontend - app/signup/page.tsx):**

```typescript
validate: {
  notCommon: (value) => {
    const commonPatterns = ["password", "qwerty", "123456", "letmein", "welcome", "admin", "login"];
    // Strip numbers and special chars to catch variations like "Qwerty123$"
    const strippedValue = value.toLowerCase().replace(/[^a-z]/g, "");
    const hasCommonPattern = commonPatterns.some(pattern => strippedValue.includes(pattern));
    return !hasCommonPattern || "Password contains a common pattern";
  },
  hasUppercase: (value) => /[A-Z]/.test(value) || "Password must contain at least one uppercase letter",
  hasLowercase: (value) => /[a-z]/.test(value) || "Password must contain at least one lowercase letter",
  hasNumber: (value) => /\d/.test(value) || "Password must contain at least one number",
  hasSpecialChar: (value) => /[!@#$%^&*(),.?":{}|<>]/.test(value) || "Password must contain at least one special character",
},
```

The common password check now:
- Strips numbers and special characters from the input
- Checks if the remaining letters contain any common password patterns
- Catches variations like "Qwerty123$", "P@ssword1!", "Admin123$"

Now passwords must contain:
- At least 8 characters
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one number (0-9)
- At least one special character (!@#$%^&*(),.?":{}|<>)
- Not be a commonly used password

#### Preventative Measures

1. **Follow NIST Guidelines**: Modern password guidelines recommend complexity requirements and checking against known compromised passwords.

2. **Consider Password Strength Meters**: Show users real-time feedback on password strength.

3. **Block Compromised Passwords**: Consider checking passwords against databases of known leaked passwords.

4. **Defense in Depth**: Always validate on both frontend (UX) and backend (security).

---

## Logic and Performance Issues

### PERF-401: Account Creation Error

**Priority:** Critical  
**Reporter:** Support Team  
**File:** `server/routers/account.ts`

#### What Caused the Bug

After successfully inserting an account with `balance: 0` into the database, the code attempts to fetch the created account. If the fetch operation fails (returns `null` or `undefined`), the logical OR operator (`||`) returns a fallback object with an incorrect `balance: 100` instead of throwing an error. This creates a false positive where users see a $100 balance even when the database operation fails or the account cannot be retrieved.

**Vulnerable Code (lines 54-67):**

```typescript
// Fetch the created account
const account = await db.select().from(accounts).where(eq(accounts.accountNumber, accountNumber!)).get();

return (
  account || {
    id: 0,
    userId: ctx.user.id,
    accountNumber: accountNumber!,
    accountType: input.accountType,
    balance: 100,  // ❌ Wrong balance!
    status: "pending",
    createdAt: new Date().toISOString(),
  }
);
```

The fallback object masks database failures and returns misleading data to users, creating incorrect balance displays and hiding potential system issues.

#### How to Reproduce the Bug

The bug can be verified by forcing a failed database fetch operation:

1. **Before the fix:**
   - Modified the account fetch query to use a hardcoded account number `"0999999999"` that doesn't exist
   - Created a new account through the UI
   - The account was inserted with `balance: 0` in the database
   - The fetch failed because the hardcoded account number doesn't exist
   - **Console output:**
     ```
     🔍 Account fetch result: NOT FOUND (null/undefined)
     ⚠️ BUG DEMONSTRATION: Returning account with balance: 100
     ⚠️ This is the FALLBACK object because account fetch failed!
     ⚠️ Actual account in DB has balance: 0, but returning balance: 100
     ```
   - The API returned an account object with `balance: 100` even though the actual database record has `balance: 0`
   - This demonstrates the false positive being returned to the user

#### How the Fix Resolves It

The fix replaces the logical OR fallback with proper error handling. If the account cannot be retrieved after creation, an error is thrown instead of returning misleading data.

**Fixed Code (lines 54-62):**

```typescript
// Fetch the created account
const account = await db.select().from(accounts).where(eq(accounts.accountNumber, accountNumber!)).get();

if (!account) {
  throw new TRPCError({
    code: "INTERNAL_SERVER_ERROR",
    message: "Account was created but could not be retrieved. Please try again.",
  });
}

return account;
```

This ensures:
- If the insert succeeds but fetch fails, an error is thrown instead of returning false data
- Users get accurate feedback about the operation status
- No misleading balance information is returned
- System issues are properly surfaced rather than hidden

#### Preventative Measures

To avoid similar issues in the future:

1. **Avoid Fallback Objects for Database Operations**: Never return fallback or mock data when database operations fail. Always throw errors to surface issues immediately.

2. **Explicit Error Handling**: Use explicit `if (!result)` checks and throw errors rather than relying on logical operators (`||`) that can mask failures.

3. **Transaction Consistency**: Consider using database transactions to ensure atomicity between insert and select operations, preventing scenarios where insert succeeds but immediate fetch fails.

4. **Return Inserted Data Directly**: When possible, return the data from the insert operation directly rather than performing a separate fetch, reducing the chance of inconsistencies.

5. **Comprehensive Error Logging**: Log all database operation failures with sufficient context to help diagnose issues without returning false data to users.

6. **Code Review Guidelines**: Establish guidelines that prohibit fallback objects for critical database operations, especially those involving financial data.

---

### PERF-404: Transaction Sorting

**Priority:** Medium  
**Reporter:** Jane Doe  
**File:** `server/routers/account.ts`

#### What Caused the Bug

The `getTransactions` query did not include an `orderBy` clause, causing transactions to be returned in an undefined order (typically insertion order, but not guaranteed). This resulted in transaction history appearing random or inconsistent to users.

**Vulnerable Code (lines 163-166):**

```typescript
const accountTransactions = await db
  .select()
  .from(transactions)
  .where(eq(transactions.accountId, input.accountId));
```

Without explicit ordering, the database returns rows in whatever order it finds most efficient, which can vary based on:
- Database internal optimizations
- Index usage
- Data fragmentation
- Concurrent operations

#### How the Fix Resolves It

The fix adds an `orderBy` clause with descending order on `createdAt`, ensuring transactions are always sorted with the newest first.

**Fixed Code (lines 164-168):**

```typescript
// Fix for PERF-404: Sort transactions by creation date (newest first)
const accountTransactions = await db
  .select()
  .from(transactions)
  .where(eq(transactions.accountId, input.accountId))
  .orderBy(desc(transactions.createdAt));
```

This ensures:
- Transactions are consistently ordered by creation date
- Newest transactions appear first (most relevant for users)
- The order is deterministic and predictable

#### Preventative Measures

To avoid similar issues in the future:

1. **Always Specify Order**: Any query returning multiple rows that will be displayed to users should have an explicit `orderBy` clause.

2. **Code Review Checklist**: Include "Is ordering specified?" as a review item for all list/collection queries.

3. **Default Ordering Convention**: Establish a convention that all list endpoints return data in a predictable order (e.g., newest first, alphabetical, etc.).

4. **Database Indexes**: Ensure appropriate indexes exist on columns used for ordering to maintain performance.

5. **API Documentation**: Document the expected order of returned data in API specifications.

---

### PERF-406: Balance Calculation

**Priority:** Critical  
**Reporter:** Finance Team  
**File:** `server/routers/account.ts`

#### What Caused the Bug

The `fundAccount` function used a faulty loop to calculate the new balance, which introduced floating-point precision errors. Instead of simply adding the amount to the balance, the code divided the amount by 100 and added it 100 times, causing cumulative precision errors.

**Vulnerable Code (lines 131-138):**

```typescript
let finalBalance = account.balance;
for (let i = 0; i < 100; i++) {
  finalBalance = finalBalance + amount / 100;
}

return {
  transaction,
  newBalance: finalBalance, // This will be slightly off due to float precision
};
```

The issues:
1. **Floating-Point Accumulation**: Each addition of `amount / 100` introduces small precision errors (e.g., adding 0.01 one hundred times does not equal exactly 1.0 in floating-point arithmetic)
2. **Mismatch with Database**: The database was updated correctly with `account.balance + amount`, but the returned `newBalance` used the faulty calculation, causing users to see incorrect balances
3. **Cumulative Errors**: After many transactions, these small errors accumulate into noticeable discrepancies

#### How to Reproduce the Bug

1. **Before the fix:**
   - Made many small transactions on an account
   - After multiple transactions, the returned `newBalance` values showed floating-point errors (e.g., `100.00000000000001` instead of `100.00`)
   - The errors accumulated with each transaction, causing noticeable discrepancies over time

2. **After the fix:**
   - Made the same number of transactions as before
   - Verified that no floating-point errors occurred
   - The returned `newBalance` values were accurate and matched the expected amounts exactly

#### How the Fix Resolves It

The fix removes the faulty loop and calculates the balance correctly in a single operation.

**Fixed Code (lines 123-131):**

```typescript
// Fix for PERF-406: Calculate balance correctly without floating-point precision errors
const newBalance = account.balance + amount;
await db
  .update(accounts)
  .set({ balance: newBalance })
  .where(eq(accounts.id, input.accountId));

return {
  transaction,
  newBalance,
};
```

This ensures:
- The balance is calculated once, correctly
- The returned balance matches exactly what was stored in the database
- No floating-point precision errors accumulate over time

#### Preventative Measures

To avoid similar issues in the future:

1. **Avoid Unnecessary Loops for Arithmetic**: Never use loops for simple arithmetic operations that can be done in a single calculation.

2. **Use Decimal Libraries for Financial Calculations**: Consider using libraries like `decimal.js` or `big.js` for precise financial calculations if floating-point precision becomes an issue.

3. **Consistency Between Database and API Response**: Always ensure that values returned to the client match exactly what is stored in the database.

4. **Code Review for Financial Logic**: Require extra scrutiny for any code that handles monetary calculations.

5. **Remove Debug/Test Code**: The loop appears to be intentionally wrong (the comment acknowledges it). Ensure such code never makes it to production.

---

### PERF-405: Missing Transactions

**Priority:** Critical  
**Reporter:** Multiple Users  
**File:** `server/routers/account.ts`

#### What Caused the Bug

After creating a transaction in the `fundAccount` function, the code attempted to fetch "the created transaction" but used a query that returned the wrong transaction entirely.

**Vulnerable Code (line 121):**

```typescript
// Fetch the created transaction
const transaction = await db.select().from(transactions).orderBy(transactions.createdAt).limit(1).get();
```

The issues with this query:
1. **No WHERE clause**: Queries ALL transactions across ALL accounts, not just the current account
2. **Ascending order**: `orderBy(transactions.createdAt)` without `desc()` sorts oldest-first
3. **limit(1)**: Returns only one row

**Result**: This query ALWAYS returned the oldest transaction in the entire database (e.g., `id: 1, amount: $12`), regardless of what transaction was just created.

#### How to Reproduce the Bug

1. **Before the fix:**
   - Created multiple funding transactions for different amounts ($456, $789, etc.)
   - Added logging to see what transaction was returned
   - **Console output for $123 funding:**
     ```
     transaction: {
       id: 1,
       accountId: 6,
       type: 'deposit',
       amount: 12,
       description: 'Funding from card',
       ...
     }
     ```
   - The response showed `id: 1, amount: $12` even though we funded $123
   - This caused confusion as the API returned incorrect transaction details after funding

2. **After the fix:**
   - Created funding transactions for $456 and $789
   - **Console output:**
     ```
     transaction: { id: 39, amount: 456, ... }
     transaction: { id: 40, amount: 789, ... }
     ```
   - Each funding event now returns the correct newly-created transaction

#### How the Fix Resolves It

The fix adds proper filtering and ordering to fetch the correct transaction.

**Fixed Code (lines 121-131):**

```typescript

// Get the most recently created transaction for this specific account
const transaction = await db
  .select()
  .from(transactions)
  .where(eq(transactions.accountId, input.accountId))
  .orderBy(desc(transactions.createdAt))
  .limit(1)
  .get();
```

**Key differences:**

| Aspect | Old Query | Fixed Query |
|--------|-----------|-------------|
| Scope | ALL transactions in database | Only THIS account's transactions |
| Order | Ascending (oldest first) | Descending (newest first) |
| Result | Always returns oldest transaction | Returns the just-created transaction |

This ensures:
- Users see the correct transaction details immediately after funding
- The transaction ID and amount match what was just created
- No confusion about "missing" or incorrect transactions

#### Preventative Measures

To avoid similar issues in the future:

1. **Always Filter by Context**: When fetching related data, always include appropriate WHERE clauses to filter by the relevant context (accountId, userId, etc.).

2. **Specify Sort Direction Explicitly**: Always use `desc()` or `asc()` explicitly to make sort order clear and intentional.

3. **Verify Query Results**: Add logging during development to verify queries return expected data.

4. **Code Review for Query Logic**: Review all database queries to ensure they fetch the intended data, not unrelated records.

5. **Test with Multiple Records**: Test queries with multiple existing records to catch issues where wrong records are returned.

---

### PERF-407: Performance Degradation

**Priority:** High  
**Reporter:** DevOps  
**File:** `server/routers/account.ts`

#### What Caused the Bug

The `getTransactions` function had a classic **N+1 query problem**. For each transaction, it made a separate database query to fetch account details, even though all transactions belonged to the same account which was already fetched earlier.

**Vulnerable Code (lines 176-183):**

```typescript
const enrichedTransactions = [];
for (const transaction of accountTransactions) {
  // THIS QUERY RUNS FOR EVERY TRANSACTION - N+1 problem!
  const accountDetails = await db.select().from(accounts).where(eq(accounts.id, transaction.accountId)).get();

  enrichedTransactions.push({
    ...transaction,
    accountType: accountDetails?.accountType,
  });
}
```

**The problems:**
1. **Redundant queries**: All transactions are for the same account, yet we query that account N times
2. **Already have the data**: The `account` object was fetched earlier in the verification step
3. **Linear degradation**: 100 transactions = 100 extra database queries
4. **Peak usage issues**: Multiple users hitting this endpoint simultaneously compounds the problem

**Performance impact:**
- Each query has overhead (~5-20ms for connection, parsing, execution)
- 100 transactions × 10ms = 1 second of unnecessary database time
- Under load: database connection exhaustion, timeouts, system slowdown

#### How the Fix Resolves It

The fix uses the `account` object already fetched during verification instead of querying in a loop.

**Fixed Code:**

```typescript
// Fix for PERF-407: Use the account we already fetched instead of N+1 queries
// Previously, this loop queried the database for EACH transaction (N+1 problem)
const enrichedTransactions = accountTransactions.map(transaction => ({
  ...transaction,
  accountType: account.accountType,
}));
```

**Performance improvement:**
- **Before**: N + 1 database queries (1 for transactions + N for account lookups)
- **After**: 1 database query total (just for transactions)
- Eliminates O(N) database calls, making response time constant regardless of transaction count

#### Preventative Measures

To avoid similar issues in the future:

1. **Identify N+1 Patterns**: Look for database queries inside loops - this is almost always a performance problem.

2. **Reuse Fetched Data**: If you've already queried data, store it and reuse it instead of querying again.

3. **Use Query Logging**: Enable database query logging during development to spot excessive queries.

4. **Load Testing**: Test endpoints with realistic data volumes to catch performance issues before production.

5. **Use JOINs or Batch Queries**: When you need related data, use JOINs or batch queries (e.g., `WHERE id IN (...)`) instead of individual queries.

6. **Code Review for Loops**: Any loop that contains a database query should be flagged for review.

---

### PERF-408: Resource Leak

**Priority:** Critical  
**Reporter:** System Monitoring  
**File:** `lib/db/index.ts`

#### What Caused the Bug

The database initialization code created two database connections, but only one was actually used. The second connection was stored in an array but never used or closed, wasting system resources.

**Vulnerable Code:**

```typescript
const sqlite = new Database(dbPath);           // Connection 1: Used by drizzle ✓
export const db = drizzle(sqlite, { schema });

const connections: Database.Database[] = [];   // Unused array

export function initDb() {
  const conn = new Database(dbPath);           // Connection 2: Created but NEVER USED ✗
  connections.push(conn);                      // Stored but never used or closed
  
  sqlite.exec(`...`);                          // Uses sqlite, not conn!
}
```

**The problems:**
1. **Unused connection**: `conn` is created but never used - only `sqlite` is used for all operations
2. **Wasted resources**: Each database connection consumes memory and file handles
3. **Unused array**: `connections` array stores references but serves no purpose
4. **Potential accumulation**: In serverless/scaling environments, orphaned connections could accumulate

#### How to Reproduce the Bug

Added logging to show both connections being created:

```
🟢 Connection 1 (sqlite): Created - THIS ONE IS USED
🔴 Connection 2 (conn): Created but NEVER USED - WASTED RESOURCE!
```

This confirmed that two connections were created on startup, but only one was actually used by drizzle for database operations.

#### How the Fix Resolves It

The fix removes the unused connection and array, keeping only the single connection used by drizzle.

**Fixed Code:**

```typescript
const dbPath = "bank.db";

// Fix for PERF-408: Single database connection used by drizzle
const sqlite = new Database(dbPath);
export const db = drizzle(sqlite, { schema });

export function initDb() {
  // Create tables if they don't exist
  sqlite.exec(`...`);
}

// Initialize database on import
initDb();
```

This ensures:
- Only one database connection is created
- No wasted resources from unused connections

#### Preventative Measures

To avoid similar issues in the future:

1. **Review Resource Creation**: Any code that creates connections, file handles, or other resources should be reviewed to ensure they're actually used.

2. **Remove Dead Code**: Unused variables, arrays, and connections should be removed, not left in the codebase.

3. **Single Connection Pattern**: For SQLite and similar embedded databases, use a single connection instance rather than creating multiple.

4. **Resource Monitoring**: Use monitoring tools to track open connections and file handles in production.


---
