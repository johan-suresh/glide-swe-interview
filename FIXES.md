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
