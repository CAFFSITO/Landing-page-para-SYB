import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import AdminLoginForm from "@/components/admin/AdminLoginForm";

export default async function AdminLoginPage() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (user?.user_metadata?.role === "admin") {
    redirect("/admin");
  }

  return <AdminLoginForm />;
}
