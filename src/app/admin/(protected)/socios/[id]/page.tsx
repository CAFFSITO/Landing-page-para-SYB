import { redirect } from 'next/navigation';
import Link from 'next/link';
import { createAdminClient } from '@/lib/supabase/server';
import { SocioDetailShell } from '@/components/admin/socios/SocioDetailShell';
import type { Socio, Entregable, Reunion, Reporte, Lectura } from '@/types';

export default async function SocioDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const supabase = createAdminClient();

  const [
    { data: socio },
    { data: entregables },
    { data: reuniones },
    { data: reportes },
    { data: lecturas },
  ] = await Promise.all([
    supabase.from('socios').select('*').eq('id', id).single<Socio>(),
    supabase
      .from('entregables')
      .select('*')
      .eq('socio_id', id)
      .order('fase')
      .order('orden')
      .returns<Entregable[]>(),
    supabase
      .from('reuniones')
      .select('*')
      .eq('socio_id', id)
      .order('fase')
      .order('numero')
      .returns<Reunion[]>(),
    supabase
      .from('reportes')
      .select('*')
      .eq('socio_id', id)
      .order('fase')
      .order('numero')
      .returns<Reporte[]>(),
    supabase
      .from('lecturas')
      .select('*')
      .eq('socio_id', id)
      .order('leido_at', { ascending: false })
      .returns<Lectura[]>(),
  ]);

  if (!socio) {
    redirect('/admin/socios');
  }

  return (
    <div style={{ maxWidth: '1000px' }}>
      <Link
        href="/admin/socios"
        style={{
          color: 'rgba(157,92,192,0.7)',
          fontSize: '0.875rem',
          textDecoration: 'none',
          display: 'inline-block',
          marginBottom: '24px',
        }}
      >
        ← Socios
      </Link>

      <div
        style={{
          backgroundColor: '#1C0D35',
          border: '1px solid rgba(157,92,192,0.2)',
          borderRadius: '12px',
          padding: '24px',
          marginBottom: '32px',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            flexWrap: 'wrap',
            gap: '16px',
          }}
        >
          <div>
            <h1
              style={{
                fontFamily: 'Merriweather, Georgia, serif',
                fontWeight: 700,
                fontSize: '1.5rem',
                color: '#FFFFFF',
                margin: '0 0 4px',
              }}
            >
              {socio.nombre}
            </h1>
            {socio.empresa && (
              <p
                style={{
                  color: 'rgba(157,92,192,0.7)',
                  margin: '0 0 12px',
                  fontSize: '0.875rem',
                }}
              >
                {socio.empresa}
              </p>
            )}
            <p
              style={{
                color: 'rgba(255,255,255,0.5)',
                margin: 0,
                fontSize: '0.8rem',
              }}
            >
              {socio.email}
            </p>
          </div>
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'flex-end',
              gap: '8px',
            }}
          >
            <span
              style={{
                display: 'inline-block',
                padding: '3px 10px',
                borderRadius: '20px',
                fontSize: '0.75rem',
                fontWeight: 600,
                backgroundColor: socio.activo
                  ? 'rgba(34,197,94,0.15)'
                  : 'rgba(239,68,68,0.1)',
                color: socio.activo ? '#22c55e' : '#ef4444',
                border: `1px solid ${
                  socio.activo
                    ? 'rgba(34,197,94,0.3)'
                    : 'rgba(239,68,68,0.2)'
                }`,
              }}
            >
              {socio.activo ? 'Activo' : 'Inactivo'}
            </span>
            <span
              style={{
                fontSize: '0.75rem',
                color: 'rgba(157,92,192,0.6)',
                fontFamily: 'monospace',
              }}
            >
              Token: {socio.token.slice(0, 24)}…
            </span>
          </div>
        </div>
      </div>

      <SocioDetailShell
        socio={socio}
        entregables={entregables ?? []}
        reuniones={reuniones ?? []}
        reportes={reportes ?? []}
        lecturas={lecturas ?? []}
      />
    </div>
  );
}
