"use client";

import { useActionState } from "react";
import { adminLoginWithToken } from "@/app/actions/admin-auth";

const initialState = { error: null };

export default function AdminLoginForm() {
  const [state, formAction, isPending] = useActionState(
    adminLoginWithToken,
    initialState
  );

  const inputStyle: React.CSSProperties = {
    width: "100%",
    backgroundColor: "#0F0720",
    border: "1.5px solid rgba(157,92,192,0.4)",
    borderRadius: "6px",
    padding: "12px 16px",
    color: "#FFFFFF",
    fontSize: "1rem",
    outline: "none",
    boxSizing: "border-box",
    fontFamily: "inherit",
  };

  return (
    <div
      style={{ backgroundColor: "#0D0618", minHeight: "100vh" }}
      className="flex flex-col items-center justify-center px-4"
    >
      <div className="mb-8 flex flex-col items-center gap-2">
        <svg
          width="56"
          height="50"
          viewBox="0 0 56 50"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          aria-label="Logo SYB"
        >
          <polygon points="28,2 54,48 2,48" fill="#9D5CC0" />
          <polygon points="28,14 44,42 12,42" fill="#1C0D35" />
        </svg>
        <span
          style={{
            fontFamily: "Merriweather, Georgia, serif",
            fontWeight: 700,
            fontSize: "1.25rem",
            color: "#FFFFFF",
            letterSpacing: "0.12em",
          }}
        >
          SYB Admin
        </span>
      </div>

      <div
        style={{
          backgroundColor: "#1C0D35",
          border: "1px solid rgba(157,92,192,0.25)",
          borderRadius: "12px",
          padding: "32px",
          width: "100%",
          maxWidth: "400px",
          boxShadow: "0 2px 20px rgba(59,30,99,0.15)",
        }}
      >
        <h1
          style={{
            fontFamily: "Merriweather, Georgia, serif",
            fontWeight: 700,
            fontSize: "1.5rem",
            color: "#FFFFFF",
            marginBottom: "8px",
          }}
        >
          Panel de administración
        </h1>
        <p
          style={{
            fontSize: "0.875rem",
            color: "rgba(157,92,192,0.6)",
            marginBottom: "28px",
          }}
        >
          Acceso exclusivo para administradores
        </p>

        <form
          action={formAction}
          style={{ display: "flex", flexDirection: "column", gap: "20px" }}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <label
              htmlFor="email"
              style={{ fontSize: "0.875rem", color: "#c4b8d4", fontWeight: 500 }}
            >
              Email
            </label>
            <input
              id="email"
              name="email"
              type="email"
              autoComplete="email"
              required
              style={inputStyle}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = "#9D5CC0";
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = "rgba(157,92,192,0.4)";
              }}
            />
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <label
              htmlFor="token"
              style={{ fontSize: "0.875rem", color: "#c4b8d4", fontWeight: 500 }}
            >
              Token de acceso
            </label>
            <input
              id="token"
              name="token"
              type="password"
              autoComplete="off"
              required
              style={inputStyle}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = "#9D5CC0";
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = "rgba(157,92,192,0.4)";
              }}
            />
          </div>

          <button
            type="submit"
            disabled={isPending}
            style={{
              width: "100%",
              padding: "14px",
              background: isPending
                ? "rgba(157,92,192,0.5)"
                : "linear-gradient(135deg, #3B1E63, #9D5CC0)",
              color: "#FFFFFF",
              fontFamily: "Merriweather, Georgia, serif",
              fontWeight: 700,
              fontSize: "1rem",
              borderRadius: "6px",
              border: "none",
              cursor: isPending ? "not-allowed" : "pointer",
              transition: "filter 200ms ease",
            }}
            onMouseEnter={(e) => {
              if (!isPending) e.currentTarget.style.filter = "brightness(1.15)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.filter = "brightness(1)";
            }}
          >
            {isPending ? "Verificando..." : "Ingresar"}
          </button>

          {state?.error && (
            <p
              style={{
                color: "#EF4444",
                fontSize: "0.875rem",
                textAlign: "center",
                margin: 0,
              }}
            >
              {state.error}
            </p>
          )}
        </form>
      </div>
    </div>
  );
}
