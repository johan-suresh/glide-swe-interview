# Bug Fixes Documentation

This document tracks all bug fixes implemented for the SecureBank application, organized by issue category.

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

#### Preventative Measures

To avoid similar issues in the future:

1. **Security Review Checklist**: Create a security review checklist that includes verifying all sensitive PII fields (SSN, credit card numbers, bank account numbers, etc.) are properly hashed or encrypted before database insertion.

2. **Type Safety with Sensitive Fields**: Consider creating a TypeScript type or utility function that marks sensitive fields, making it impossible to accidentally insert them without hashing:
   ```typescript
   type SensitiveField<T> = T & { __sensitive: true };
   ```

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
