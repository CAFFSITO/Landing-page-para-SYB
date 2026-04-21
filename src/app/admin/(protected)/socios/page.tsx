import { createAdminClient } from "@/lib/supabase/server";
import Link from "next/link";
import SociosTable from "@/components/admin/socios/SociosTable";

export default async function SociosPage() {
  const supabase = createAdminClient();
  const { data: socios } = await supabase
    .from("socios")
    .select("*")
    .order("created_at", { ascending: false });

  return (
    <div style={{ padding: "32px" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: "24px",
        }}
      >
        <h1
          style={{
            fontFamily: "Merriweather, Georgia, serif",
            color: "#FFFFFF",
            fontSize: "1.75rem",
            margin: 0,
          }}
        >
          Socios
        </h1>
        <Link
          href="/admin/socios/nuevo"
          style={{
            backgroundColor: "#9D5CC0",
            color: "#FFFFFF",
            padding: "8px 16px",
            borderRadius: "8px",
            textDecoration: "none",
            fontSize: "0.875rem",
          }}
        >
          + Crear nuevo socio
        </Link>
      </div>
      <SociosTable socios={socios ?? []} />
    </div>
  );
}
