import { redirect } from "next/navigation";
import { createAdminClient } from "@/lib/supabase/server";
import Navbar from "@/components/landing/navbar";
import Hero from "@/components/landing/hero";
import ProblemSection from "@/components/landing/problem-section";
import MethodologySection from "@/components/landing/methodology-section";
import PillarsSection from "@/components/landing/pillars-section";
import GuaranteeSection from "@/components/landing/guarantee-section";
import CtaFinal from "@/components/landing/cta-final";
import Footer from "@/components/landing/footer";

type HomeProps = {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
};

export default async function Home({ searchParams }: HomeProps) {
  const params = await searchParams;
  const token = typeof params.token === "string" ? params.token : null;

  // Si viene un token en la URL, validamos contra la tabla socios
  if (token) {
    const supabase = createAdminClient();
    const { data: socio } = await supabase
      .from("socios")
      .select("id")
      .eq("token", token)
      .eq("activo", true)
      .single();

    if (socio) {
      redirect(`/login?token=${token}`);
    }
  }

  return (
    <>
      <Navbar />
      <main>
        <Hero />
        <ProblemSection />
        <MethodologySection />
        <PillarsSection />
        <GuaranteeSection />
        <CtaFinal />
      </main>
      <Footer />
    </>
  );
}
