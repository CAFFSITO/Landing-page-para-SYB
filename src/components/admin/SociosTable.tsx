"use client";

import Link from "next/link";

import type { Socio } from "@/types";

export type SocioRow = Pick<
  Socio,
  | "id"
  | "nombre"
  | "empresa"
  | "fase_actual"
  | "fase_1_done"
  | "fase_2_done"
  | "fase_3_done"
  | "activo"
  | "created_at"
>;

type Props = {
  socios: SocioRow[];
  ultimaActividad: Record<string, string>;
};

function tiempoRelativo(fechaStr: string | undefined): string {
  if (!fechaStr) return "Nunca";
  const diff = Date.now() - new Date(fechaStr).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "Hace un momento";
  if (mins < 60) return `Hace ${mins} min`;
  const hs = Math.floor(mins / 60);
  if (hs < 24) return `Hace ${hs} h`;
  const dias = Math.floor(hs / 24);
  if (dias === 1) return "Hace 1 día";
  if (dias < 30) return `Hace ${dias} días`;
  const meses = Math.floor(dias / 30);
  if (meses === 1) return "Hace 1 mes";
  return `Hace ${meses} meses`;
}

function calcularProgreso(socio: SocioRow): number {
  const done = [socio.fase_1_done, socio.fase_2_done, socio.fase_3_done].filter(Boolean).length;
  return Math.round((done / 3) * 100);
}

export default function SociosTable({ socios, ultimaActividad }: Props) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          fontSize: "0.875rem",
        }}
      >
        <thead>
          <tr style={{ borderBottom: "1px solid rgba(157,92,192,0.15)" }}>
            {["Nombre", "Empresa", "Fase", "Progreso", "Última actividad", "Acciones"].map(
              (col) => (
                <th
                  key={col}
                  style={{
                    padding: "12px 16px",
                    textAlign: "left",
                    fontSize: "0.7rem",
                    color: "rgba(157,92,192,0.7)",
                    textTransform: "uppercase",
                    letterSpacing: "0.08em",
                    fontWeight: 600,
                    whiteSpace: "nowrap",
                  }}
                >
                  {col}
                </th>
              )
            )}
          </tr>
        </thead>

        <tbody>
          {socios.length === 0 ? (
            <tr>
              <td
                colSpan={6}
                style={{
                  padding: "40px 16px",
                  textAlign: "center",
                  color: "rgba(255,255,255,0.3)",
                }}
              >
                No hay socios activos.
              </td>
            </tr>
          ) : (
            socios.map((socio, idx) => {
              const progreso = calcularProgreso(socio);
              const ultimaAct = ultimaActividad[socio.id];

              return (
                <tr
                  key={socio.id}
                  style={{
                    borderBottom:
                      idx < socios.length - 1
                        ? "1px solid rgba(157,92,192,0.08)"
                        : "none",
                    transition: "background 150ms ease",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = "rgba(157,92,192,0.05)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = "transparent";
                  }}
                >
                  <td
                    style={{
                      padding: "14px 16px",
                      color: "#FFFFFF",
                      fontFamily: "Merriweather, Georgia, serif",
                      fontWeight: 700,
                      whiteSpace: "nowrap",
                    }}
                  >
                    {socio.nombre}
                  </td>

                  <td
                    style={{
                      padding: "14px 16px",
                      color: "rgba(255,255,255,0.6)",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {socio.empresa ?? "—"}
                  </td>

                  <td style={{ padding: "14px 16px", whiteSpace: "nowrap" }}>
                    <span
                      style={{
                        display: "inline-block",
                        padding: "3px 10px",
                        borderRadius: "20px",
                        fontSize: "0.75rem",
                        fontWeight: 600,
                        backgroundColor: "rgba(157,92,192,0.15)",
                        color: "#9D5CC0",
                        border: "1px solid rgba(157,92,192,0.3)",
                      }}
                    >
                      Fase {socio.fase_actual}
                    </span>
                  </td>

                  <td style={{ padding: "14px 16px", minWidth: "120px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <div
                        style={{
                          flex: 1,
                          height: "6px",
                          backgroundColor: "rgba(157,92,192,0.15)",
                          borderRadius: "3px",
                          overflow: "hidden",
                          minWidth: "60px",
                        }}
                      >
                        <div
                          style={{
                            height: "100%",
                            width: `${progreso}%`,
                            background: "linear-gradient(90deg, #9D5CC0, #C084FC)",
                            borderRadius: "3px",
                            transition: "width 600ms ease",
                          }}
                        />
                      </div>
                      <span
                        style={{
                          fontSize: "0.75rem",
                          color: "rgba(255,255,255,0.5)",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {progreso}%
                      </span>
                    </div>
                  </td>

                  <td
                    style={{
                      padding: "14px 16px",
                      color: "rgba(255,255,255,0.4)",
                      fontSize: "0.8rem",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {tiempoRelativo(ultimaAct)}
                  </td>

                  <td style={{ padding: "14px 16px", whiteSpace: "nowrap" }}>
                    <div style={{ display: "flex", gap: "8px" }}>
                      <Link
                        href="/lobby"
                        style={{
                          padding: "5px 12px",
                          fontSize: "0.75rem",
                          borderRadius: "6px",
                          backgroundColor: "rgba(157,92,192,0.15)",
                          color: "#9D5CC0",
                          border: "1px solid rgba(157,92,192,0.3)",
                          textDecoration: "none",
                          fontFamily: "inherit",
                          transition: "background 150ms ease",
                        }}
                      >
                        Ver lobby
                      </Link>
                      <Link
                        href={`/admin/socios/${socio.id}`}
                        style={{
                          padding: "5px 12px",
                          fontSize: "0.75rem",
                          borderRadius: "6px",
                          backgroundColor: "transparent",
                          color: "rgba(255,255,255,0.5)",
                          border: "1px solid rgba(255,255,255,0.1)",
                          textDecoration: "none",
                          fontFamily: "inherit",
                          transition: "color 150ms ease, border-color 150ms ease",
                        }}
                      >
                        Editar
                      </Link>
                    </div>
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
