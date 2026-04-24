import { createAdminClient } from "@/lib/supabase/server";
import SociosTable, { type SocioRow } from "@/components/admin/SociosTable";

type LecturaMin = {
  socio_id: string;
  leido_at: string;
};

export default async function AdminPage() {
  const supabase = createAdminClient();

  const [{ data: socios }, { data: lecturas }] = await Promise.all([
    supabase
      .from("socios")
      .select(
        "id, nombre, empresa, fase_actual, fase_1_done, fase_2_done, fase_3_done, activo, created_at"
      )
      .eq("activo", true)
      .returns<SocioRow[]>(),

    supabase
      .from("lecturas")
      .select("socio_id, leido_at")
      .order("leido_at", { ascending: false })
      .returns<LecturaMin[]>(),
  ]);

  const sociosList = socios ?? [];
  const lecturasList = lecturas ?? [];

  const ultimaActividadMap = new Map<string, string>();
  for (const l of lecturasList) {
    if (!ultimaActividadMap.has(l.socio_id)) {
      ultimaActividadMap.set(l.socio_id, l.leido_at);
    }
  }

  const sociosOrdenados = [...sociosList].sort((a, b) => {
    const ua = ultimaActividadMap.get(a.id);
    const ub = ultimaActividadMap.get(b.id);
    if (!ua && !ub) return 0;
    if (!ua) return 1;
    if (!ub) return -1;
    return new Date(ub).getTime() - new Date(ua).getTime();
  });

  const ultimaActividad = Object.fromEntries(ultimaActividadMap);

  const totalActivos = sociosList.length;
  const enFase1 = sociosList.filter((s) => s.fase_actual === 1).length;
  const enFase3 = sociosList.filter((s) => s.fase_actual === 3).length;

  const cardStyle: React.CSSProperties = {
    backgroundColor: "#1C0D35",
    border: "1px solid rgba(157,92,192,0.2)",
    borderRadius: "12px",
    padding: "24px",
    flex: "1 1 0",
    minWidth: "160px",
  };

  const labelStyle: React.CSSProperties = {
    fontSize: "0.7rem",
    color: "rgba(157,92,192,0.7)",
    textTransform: "uppercase",
    letterSpacing: "0.1em",
    marginBottom: "8px",
  };

  const valueStyle: React.CSSProperties = {
    fontFamily: "Merriweather, Georgia, serif",
    fontWeight: 700,
    fontSize: "2.25rem",
    color: "#FFFFFF",
    margin: 0,
  };

  return (
    <div style={{ maxWidth: "1100px" }}>
      <h1
        style={{
          fontFamily: "Merriweather, Georgia, serif",
          fontWeight: 700,
          fontSize: "1.5rem",
          color: "#FFFFFF",
          marginBottom: "32px",
        }}
      >
        Dashboard
      </h1>

      <div
        style={{
          display: "flex",
          gap: "20px",
          marginBottom: "40px",
          flexWrap: "wrap",
        }}
      >
        <div style={cardStyle}>
          <p style={labelStyle}>Socios activos</p>
          <p style={valueStyle}>{totalActivos}</p>
        </div>

        <div style={cardStyle}>
          <p style={labelStyle}>En Fase 1</p>
          <p style={valueStyle}>{enFase1}</p>
        </div>

        <div style={cardStyle}>
          <p style={labelStyle}>En Fase 3</p>
          <p style={valueStyle}>{enFase3}</p>
        </div>
      </div>

      <div
        style={{
          backgroundColor: "#1C0D35",
          border: "1px solid rgba(157,92,192,0.2)",
          borderRadius: "12px",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            padding: "20px 24px",
            borderBottom: "1px solid rgba(157,92,192,0.15)",
          }}
        >
          <h2
            style={{
              fontFamily: "Merriweather, Georgia, serif",
              fontWeight: 700,
              fontSize: "1rem",
              color: "#FFFFFF",
              margin: 0,
            }}
          >
            Socios
          </h2>
        </div>

        <SociosTable socios={sociosOrdenados} ultimaActividad={ultimaActividad} />
      </div>
    </div>
  );
}
