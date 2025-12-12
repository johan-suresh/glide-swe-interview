"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { httpBatchLink } from "@trpc/client";
import React, { useState } from "react";
import { trpc } from "./client";

export function TRPCProvider({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 60 * 1000,
            retry: (failureCount, error: any) => {
              // Don't retry on auth errors
              if (error?.data?.code === "UNAUTHORIZED") return false;
              return failureCount < 3;
            },
          },
          mutations: {
            onError: (error: any) => {
              // Redirect to login on unauthorized errors
              if (error?.data?.code === "UNAUTHORIZED" && typeof window !== "undefined") {
                window.location.href = "/login";
              }
            },
          },
        },
      })
  );

  const [trpcClient] = useState(() =>
    trpc.createClient({
      links: [
        httpBatchLink({
          url: "/api/trpc",
          fetch(url, options) {
            return fetch(url, {
              ...options,
              credentials: "same-origin",
            } as RequestInit).then(async (response) => {
              // Check for 401 and redirect to login
              if (response.status === 401 && typeof window !== "undefined") {
                // Clone response so we can still return it
                const cloned = response.clone();
                const data = await cloned.json().catch(() => null);
                if (data?.error?.data?.code === "UNAUTHORIZED" || data?.[0]?.error?.data?.code === "UNAUTHORIZED") {
                  window.location.href = "/login";
                }
              }
              return response;
            });
          },
        }),
      ],
    })
  );

  return (
    <trpc.Provider client={trpcClient} queryClient={queryClient}>
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    </trpc.Provider>
  );
}
