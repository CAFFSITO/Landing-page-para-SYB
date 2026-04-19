import { redirect } from "next/navigation";
import { createAdminClient } from "@/lib/supabase/server";
import LoginForm from "@/components/landing/login-form";

type PageProps = {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
};

export default async function LoginPage({ searchParams }: PageProps) {
  const params = await searchParams;
  const token = typeof params.token === "string" ? params.token : null;

  // Sin token no hay acceso — redirigir a la landing
  if (!token) {
    redirect("/");
  }

  const supabase = createAdminClient();

  // Validamos que el token corresponda a un socio activo
  const { data: socio } = await supabase
    .from("socios")
    .select("id, activo")
    .eq("token", token)
    .single();

  if (!socio || !socio.activo) {
    redirect("/");
  }

  return <LoginForm token={token} />;
}
