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
- **Before**: 1 + N database queries (1 for transactions + N for account lookups)
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
