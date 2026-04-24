"use server";

import { createAdminClient, createClient } from "@/lib/supabase/server";
import { redirect } from "next/navigation";

/**
 * Autentica un administrador buscando email + token en la tabla admin_users.
 *
 * Usa el cliente con Service Role para bypassear RLS, consultar admin_users,
 * y crear una sesión real de Supabase Auth con el user_id asociado.
 */
export async function adminLoginWithToken(
  _prevState: { error: string | null },
  formData: FormData
): Promise<{ error: string | null }> {
  const email = (formData.get("email") as string)?.trim().toLowerCase();
  const token = (formData.get("token") as string)?.trim();

  if (!email || !token) {
    return { error: "Por favor completá todos los campos." };
  }

  // Usamos el cliente admin (service role) para leer admin_users sin RLS.
  const adminClient = createAdminClient();

  const { data: adminUser, error: dbError } = await adminClient
    .from("admin_users")
    .select("user_id, activo")
    .eq("email", email)
    .eq("token", token)
    .single();

  if (dbError || !adminUser) {
    return { error: "Credenciales incorrectas. Intentá de nuevo." };
  }

  if (!adminUser.activo) {
    return { error: "Tu cuenta de administrador está desactivada." };
  }

  // 1. Generamos un código OTP (Magic Link) como administradores.
  // Esto NO envía un email, solo nos devuelve los códigos generados.
  const { data: linkData, error: linkError } = await adminClient.auth.admin.generateLink({
    type: "magiclink",
    email: email,
  });

  if (linkError || !linkData?.properties?.email_otp) {
    console.error("[admin-auth] Error al generar link:", linkError?.message);
    return { error: "No se pudo generar la sesión de administrador." };
  }

  // 2. Usamos el cliente regular para verificar ese OTP.
  // Al verificarlo con el cliente regular (createClient), automáticamente
  // se setean las cookies de sesión en el navegador del usuario.
  const supabase = await createClient();
  const { data: sessionData, error: sessionError } = await supabase.auth.verifyOtp({
    email: email,
    token: linkData.properties.email_otp,
    type: "magiclink",
  });

  if (sessionError || !sessionData?.session) {
    console.error("[admin-auth] Error al verificar OTP:", sessionError?.message);
    return { error: "No se pudo iniciar sesión. Contactá al soporte." };
  }

  redirect("/admin");
}
