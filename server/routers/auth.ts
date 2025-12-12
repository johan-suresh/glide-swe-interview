import { z } from "zod";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { TRPCError } from "@trpc/server";
import { publicProcedure, router } from "../trpc";
import { db } from "@/lib/db";
import { users, sessions } from "@/lib/db/schema";
import { eq } from "drizzle-orm";

export const authRouter = router({
  signup: publicProcedure
    .input(
      z.object({
        // Fix for VAL-201: Enhanced email validation with valid TLD check
        email: z.string()
          .email("Invalid email address")
          .toLowerCase()
          .refine((email) => {
            // Check for valid top-level domains
            const validTLDs = [".com", ".org", ".net", ".edu", ".gov", ".mil", ".co", ".io", ".dev", ".app", ".me", ".info", ".biz", ".us", ".uk", ".ca", ".au", ".de", ".fr", ".jp", ".cn", ".in", ".br", ".mx", ".es", ".it", ".nl", ".se", ".no", ".fi", ".dk", ".pl", ".ru", ".ch", ".at", ".be", ".nz", ".ie", ".sg", ".hk", ".kr", ".tw", ".za"];
            return validTLDs.some(tld => email.endsWith(tld));
          }, "Please use a valid email domain (e.g., .com, .org, .edu)"),
        // Fix for VAL-208: Strong password requirements
        password: z.string()
          .min(8, "Password must be at least 8 characters")
          .refine((val) => /[A-Z]/.test(val), "Password must contain at least one uppercase letter")
          .refine((val) => /[a-z]/.test(val), "Password must contain at least one lowercase letter")
          .refine((val) => /\d/.test(val), "Password must contain at least one number")
          .refine((val) => /[!@#$%^&*(),.?":{}|<>]/.test(val), "Password must contain at least one special character")
          .refine((val) => {
            const commonPatterns = ["password", "qwerty", "123456", "letmein", "welcome", "admin", "login", "abc123", "master"];
            const strippedValue = val.toLowerCase().replace(/[^a-z]/g, "");
            return !commonPatterns.some(pattern => strippedValue.includes(pattern));
          }, "Password contains a common pattern"),
        firstName: z.string().min(1),
        lastName: z.string().min(1),
        phoneNumber: z.string().regex(/^\+?\d{10,15}$/),
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
        ssn: z.string().regex(/^\d{9}$/),
        address: z.string().min(1),
        city: z.string().min(1),
        // Fix for VAL-203: Validate actual US state codes
        state: z.string().length(2).toUpperCase().refine((val) => {
          const validStates = ["AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY", "DC", "PR", "VI", "GU", "AS", "MP"];
          return validStates.includes(val);
        }, "Invalid US state code"),
        zipCode: z.string().regex(/^\d{5}$/),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const existingUser = await db.select().from(users).where(eq(users.email, input.email)).get();

      if (existingUser) {
        throw new TRPCError({
          code: "CONFLICT",
          message: "User already exists",
        });
      }

      const hashedPassword = await bcrypt.hash(input.password, 10);
      const hashedSSN = await bcrypt.hash(input.ssn, 10); //Fix for SEC-301

      await db.insert(users).values({
        ...input,
        password: hashedPassword,
        ssn: hashedSSN, //storing hashed and saltedSSN in the database instead of plain text 
      });

      // Fetch the created user
      const user = await db.select().from(users).where(eq(users.email, input.email)).get();

      if (!user) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to create user",
        });
      }

      // Create session
      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || "temporary-secret-for-interview", {
        expiresIn: "7d",
      });

      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      // Fix for SEC-304: Invalidate all existing sessions before creating new one (single session policy)
      await db.delete(sessions).where(eq(sessions.userId, user.id));

      await db.insert(sessions).values({
        userId: user.id,
        token,
        expiresAt: expiresAt.toISOString(),
      });

      // Set cookie
      if ("setHeader" in ctx.res) {
        ctx.res.setHeader("Set-Cookie", `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
      } else {
        (ctx.res as Headers).set("Set-Cookie", `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
      }

      // Fix for SEC-301: Don't return sensitive data (password, SSN) in API response
      return { user: { ...user, password: undefined, ssn: undefined }, token };
    }),

  login: publicProcedure
    .input(
      z.object({
        email: z.string().email(),
        password: z.string(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const user = await db.select().from(users).where(eq(users.email, input.email)).get();

      if (!user) {
        throw new TRPCError({
          code: "UNAUTHORIZED",
          message: "Invalid credentials",
        });
      }

      const validPassword = await bcrypt.compare(input.password, user.password);

      if (!validPassword) {
        throw new TRPCError({
          code: "UNAUTHORIZED",
          message: "Invalid credentials",
        });
      }

      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || "temporary-secret-for-interview", {
        expiresIn: "7d",
      });

      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      // Fix for SEC-304: Invalidate all existing sessions before creating new one (single session policy)
      await db.delete(sessions).where(eq(sessions.userId, user.id));

      await db.insert(sessions).values({
        userId: user.id,
        token,
        expiresAt: expiresAt.toISOString(),
      });

      if ("setHeader" in ctx.res) {
        ctx.res.setHeader("Set-Cookie", `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
      } else {
        (ctx.res as Headers).set("Set-Cookie", `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
      }

      // Fix for SEC-301: Don't return sensitive data (password, SSN) in API response
      return { user: { ...user, password: undefined, ssn: undefined }, token };
    }),

  logout: publicProcedure.mutation(async ({ ctx }) => {
    if (ctx.user) {
      // Delete session from database
      let token: string | undefined;
      if ("cookies" in ctx.req) {
        token = (ctx.req as any).cookies.session;
      } else {
        const cookieHeader = ctx.req.headers.get?.("cookie") || (ctx.req.headers as any).cookie;
        token = cookieHeader
          ?.split("; ")
          .find((c: string) => c.startsWith("session="))
          ?.split("=")[1];
      }
      if (token) {
        await db.delete(sessions).where(eq(sessions.token, token));
      }
    }

    if ("setHeader" in ctx.res) {
      ctx.res.setHeader("Set-Cookie", `session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
    } else {
      (ctx.res as Headers).set("Set-Cookie", `session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
    }

    return { success: true, message: ctx.user ? "Logged out successfully" : "No active session" };
  }),
});
