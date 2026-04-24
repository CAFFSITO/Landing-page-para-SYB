import { createServerClient } from "@supabase/ssr";
import { NextRequest, NextResponse } from "next/server";

export async function middleware(request: NextRequest) {
  // Construimos la respuesta base para poder mutar cookies si el token se refresca
  let supabaseResponse = NextResponse.next({ request });

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          // Primero actualizamos el request para que los Server Components vean los nuevos valores
          cookiesToSet.forEach(({ name, value }) =>
            request.cookies.set(name, value)
          );
          // Recreamos la respuesta con el request actualizado y copiamos las cookies al response
          supabaseResponse = NextResponse.next({ request });
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options)
          );
        },
      },
    }
  );

  // getUser() valida el token contra el servidor de Auth — seguro para decisiones de autorización
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const { pathname } = request.nextUrl;

  // Proteger /lobby — requiere sesión activa
  if (pathname.startsWith("/lobby")) {
    if (!user) {
      return NextResponse.redirect(new URL("/", request.url));
    }
  }

  // Proteger /admin — requiere sesión activa Y rol de administrador
  // /admin/login queda excluido para que el form sea accesible sin sesión
  if (pathname.startsWith("/admin") && pathname !== "/admin/login") {
    if (!user) {
      return NextResponse.redirect(new URL("/admin/login", request.url));
    }
    if (user.user_metadata?.role !== "admin") {
      return NextResponse.redirect(new URL("/admin/login", request.url));
    }
  }

  return supabaseResponse;
}

export const config = {
  matcher: [
    // Excluir archivos estáticos, imágenes optimizadas, favicon y archivos con extensión
    "/((?!_next/static|_next/image|favicon\\.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|css|js)$).*)",
  ],
};
