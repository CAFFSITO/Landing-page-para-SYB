import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import AdminNavbar from "@/components/admin/AdminNavbar";
import AdminSidebar from "@/components/admin/AdminSidebar";

export default async function AdminProtectedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const supabase = await createClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user || user.user_metadata?.role !== "admin") {
    redirect("/admin/login");
  }

  return (
    <div style={{ minHeight: "100vh", backgroundColor: "#0D0618" }}>
      <AdminNavbar />

      <div style={{ display: "flex" }}>
        <AdminSidebar />

        <main
          style={{
            flex: 1,
            padding: "40px 32px",
            minHeight: "calc(100vh - 56px)",
            overflowX: "hidden",
          }}
        >
          {children}
        </main>
      </div>
    </div>
  );
}
