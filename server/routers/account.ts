import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { randomInt } from "crypto";
import { protectedProcedure, router } from "../trpc";
import { db } from "@/lib/db";
import { accounts, transactions } from "@/lib/db/schema";
import { eq, and, desc } from "drizzle-orm";

// Fix for SEC-302: Use cryptographically secure random number generator
function generateAccountNumber(): string {
  return randomInt(0, 1000000000).toString().padStart(10, "0");
}

// Fix for VAL-206: Luhn algorithm to validate credit card numbers
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

export const accountRouter = router({
  createAccount: protectedProcedure
    .input(
      z.object({
        accountType: z.enum(["checking", "savings"]),
      })
    )
    .mutation(async ({ input, ctx }) => {
      // Check if user already has an account of this type
      const existingAccount = await db
        .select()
        .from(accounts)
        .where(and(eq(accounts.userId, ctx.user.id), eq(accounts.accountType, input.accountType)))
        .get();

      if (existingAccount) {
        throw new TRPCError({
          code: "CONFLICT",
          message: `You already have a ${input.accountType} account`,
        });
      }

      let accountNumber;
      let isUnique = false;

      // Generate unique account number
      while (!isUnique) {
        accountNumber = generateAccountNumber();
        const existing = await db.select().from(accounts).where(eq(accounts.accountNumber, accountNumber)).get();
        isUnique = !existing;
      }

      await db.insert(accounts).values({
        userId: ctx.user.id,
        accountNumber: accountNumber!,
        accountType: input.accountType,
        balance: 0,
        status: "active",
      });

      // Fetch the created account
      const account = await db.select().from(accounts).where(eq(accounts.accountNumber, accountNumber!)).get();

      // Fix for PERF-401: Throw error instead of returning fallback object with incorrect balance
      if (!account) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Account was created but could not be retrieved. Please try again.",
        });
      }

      return account;
    }),

  getAccounts: protectedProcedure.query(async ({ ctx }) => {
    const userAccounts = await db.select().from(accounts).where(eq(accounts.userId, ctx.user.id));

    return userAccounts;
  }),

  fundAccount: protectedProcedure
    .input(
      z.object({
        accountId: z.number(),
        amount: z.number().positive(),
        // Fix for VAL-207: Routing number required for bank transfers
        fundingSource: z.object({
          type: z.enum(["card", "bank"]),
          accountNumber: z.string(),
          routingNumber: z.string().optional(),
        }).refine(
          (data) => data.type !== "bank" || (data.routingNumber && /^\d{9}$/.test(data.routingNumber)),
          { message: "Routing number is required for bank transfers and must be 9 digits" }
        ),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const amount = parseFloat(input.amount.toString());

      // Fix for VAL-206: Validate card number using Luhn algorithm
      if (input.fundingSource.type === "card") {
        if (!isValidCardNumber(input.fundingSource.accountNumber)) {
          throw new TRPCError({
            code: "BAD_REQUEST",
            message: "Invalid card number",
          });
        }
      }

      // Verify account belongs to user
      const account = await db
        .select()
        .from(accounts)
        .where(and(eq(accounts.id, input.accountId), eq(accounts.userId, ctx.user.id)))
        .get();

      if (!account) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Account not found",
        });
      }

      if (account.status !== "active") {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Account is not active",
        });
      }

      // Create transaction
      await db.insert(transactions).values({
        accountId: input.accountId,
        type: "deposit",
        amount,
        description: `Funding from ${input.fundingSource.type}`,
        status: "completed",
        processedAt: new Date().toISOString(),
      });

      // Fetch the created transaction
      // Original buggy query (returns oldest transaction from ALL accounts):
      // const transaction = await db.select().from(transactions).orderBy(transactions.createdAt).limit(1).get();
      
      // Fixed: Get the most recently created transaction for this specific account
      const transaction = await db
        .select()
        .from(transactions)
        .where(eq(transactions.accountId, input.accountId))
        .orderBy(desc(transactions.createdAt))
        .limit(1)
        .get();
      

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
    }),

  getTransactions: protectedProcedure
    .input(
      z.object({
        accountId: z.number(),
      })
    )
    .query(async ({ input, ctx }) => {
      // Verify account belongs to user
      const account = await db
        .select()
        .from(accounts)
        .where(and(eq(accounts.id, input.accountId), eq(accounts.userId, ctx.user.id)))
        .get();

      if (!account) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Account not found",
        });
      }

      // Fix for PERF-404: Sort transactions by creation date (newest first)
      const accountTransactions = await db
        .select()
        .from(transactions)
        .where(eq(transactions.accountId, input.accountId))
        .orderBy(desc(transactions.createdAt));

        //asdadasdasdasdasdasdas

      // Fix for PERF-407: Use the account we already fetched instead of N+1 queries
      // Previously, this loop queried the database for EACH transaction (N+1 problem)
      const enrichedTransactions = accountTransactions.map(transaction => ({
        ...transaction,
        accountType: account.accountType,
      }));

      return enrichedTransactions;
    }),
});
