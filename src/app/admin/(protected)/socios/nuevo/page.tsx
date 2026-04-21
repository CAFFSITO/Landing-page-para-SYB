'use client'

import { useState, useEffect, useRef } from 'react'
import { useRouter } from 'next/navigation'
import { Copy } from 'lucide-react'
import { toast, Toaster } from 'sonner'
import { createSocioAction } from '@/app/actions/socios'
import Link from 'next/link'

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? 'https://syb.vercel.app'

function slugify(str: string) {
  return str
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9-]/g, '')
}

function generatePassword(): string {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  const values = new Uint8Array(12)
  crypto.getRandomValues(values)
  return Array.from(values)
    .map((v) => charset[v % charset.length])
    .join('')
}

function inputStyle(focused: boolean): React.CSSProperties {
  return {
    width: '100%',
    backgroundColor: '#0D0618',
    border: focused ? '1px solid #9D5CC0' : '1px solid rgba(157,92,192,0.25)',
    color: '#FFFFFF',
    borderRadius: '8px',
    padding: '10px 14px',
    fontSize: '0.875rem',
    outline: 'none',
    boxSizing: 'border-box',
    transition: 'border-color 0.15s',
  }
}

function FieldError({ msg }: { msg?: string }) {
  if (!msg) return null
  return (
    <span style={{ color: '#ef4444', fontSize: '0.75rem', marginTop: '4px', display: 'block' }}>
      {msg}
    </span>
  )
}

type ModalData = {
  socioId: string
  token: string
  email: string
  password: string
}

export default function NuevoSocioPage() {
  const router = useRouter()

  const [nombre, setNombre] = useState('')
  const [email, setEmail] = useState('')
  const [empresa, setEmpresa] = useState('')
  const [token, setToken] = useState('')
  const [password, setPassword] = useState('')
  const [notas, setNotas] = useState('')
  const [loading, setLoading] = useState(false)
  const [modalData, setModalData] = useState<ModalData | null>(null)

  const [errors, setErrors] = useState<Record<string, string>>({})
  const [focused, setFocused] = useState<string | null>(null)

  const tokenManuallyEdited = useRef(false)
  const randomSuffix = useRef<number | null>(null)

  useEffect(() => {
    if (tokenManuallyEdited.current) return
    if (!nombre) {
      setToken('')
      randomSuffix.current = null
      return
    }
    if (randomSuffix.current === null) {
      randomSuffix.current = Math.floor(100 + Math.random() * 900)
    }
    setToken(`login-${slugify(nombre)}-${randomSuffix.current}`)
  }, [nombre])

  function handleTokenChange(val: string) {
    tokenManuallyEdited.current = true
    setToken(val)
  }

  function handleGeneratePassword() {
    setPassword(generatePassword())
  }

  function validate(): boolean {
    const errs: Record<string, string> = {}
    if (!nombre.trim()) errs.nombre = 'El nombre es requerido.'
    if (!email.trim()) {
      errs.email = 'El email es requerido.'
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errs.email = 'El email no es válido.'
    }
    if (!token.trim()) errs.token = 'El token es requerido.'
    if (!password.trim()) {
      errs.password = 'La contraseña es requerida.'
    } else if (password.length < 8) {
      errs.password = 'La contraseña debe tener al menos 8 caracteres.'
    }
    setErrors(errs)
    return Object.keys(errs).length === 0
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!validate()) return
    setLoading(true)
    const result = await createSocioAction({
      nombre,
      email,
      empresa: empresa || undefined,
      token,
      password,
      notas_admin: notas || undefined,
    })
    if (!result.ok) {
      toast.error(result.error)
      setLoading(false)
      return
    }
    setModalData({ socioId: result.socioId, token, email, password })
    setLoading(false)
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text)
    toast.success('Copiado')
  }

  function copyAll() {
    if (!modalData) return
    const text = [
      `Link de acceso: ${SITE_URL}/?token=${modalData.token}`,
      `Email: ${modalData.email}`,
      `Contraseña: ${modalData.password}`,
    ].join('\n')
    navigator.clipboard.writeText(text)
    toast.success('Copiado')
  }

  return (
    <>
      <div
        style={{
          minHeight: '100vh',
          backgroundColor: '#0D0618',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '40px 16px',
        }}
      >
        <div style={{ width: '100%', maxWidth: '540px' }}>
          <Link
            href="/admin/socios"
            style={{
              color: 'rgba(157,92,192,0.7)',
              textDecoration: 'none',
              fontSize: '0.875rem',
              display: 'inline-block',
              marginBottom: '16px',
            }}
          >
            ← Volver
          </Link>
          <div
            style={{
              backgroundColor: '#1C0D35',
              border: '1px solid rgba(157,92,192,0.2)',
              borderRadius: '12px',
              padding: '40px',
            }}
          >
            <h1
              style={{
                fontFamily: 'Merriweather, Georgia, serif',
                color: '#FFFFFF',
                fontSize: '1.5rem',
                margin: '0 0 28px 0',
              }}
            >
              Nuevo socio
            </h1>

            <form onSubmit={handleSubmit} noValidate>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
                <div>
                  <label
                    style={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.8rem', display: 'block', marginBottom: '6px' }}
                  >
                    Nombre *
                  </label>
                  <input
                    type="text"
                    value={nombre}
                    onChange={(e) => setNombre(e.target.value)}
                    onFocus={() => setFocused('nombre')}
                    onBlur={() => setFocused(null)}
                    style={inputStyle(focused === 'nombre')}
                  />
                  <FieldError msg={errors.nombre} />
                </div>

                <div>
                  <label
                    style={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.8rem', display: 'block', marginBottom: '6px' }}
                  >
                    Email *
                  </label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    onFocus={() => setFocused('email')}
                    onBlur={() => setFocused(null)}
                    style={inputStyle(focused === 'email')}
                  />
                  <FieldError msg={errors.email} />
                </div>

                <div>
                  <label
                    style={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.8rem', display: 'block', marginBottom: '6px' }}
                  >
                    Empresa
                  </label>
                  <input
                    type="text"
                    value={empresa}
                    onChange={(e) => setEmpresa(e.target.value)}
                    onFocus={() => setFocused('empresa')}
                    onBlur={() => setFocused(null)}
                    style={inputStyle(focused === 'empresa')}
                  />
                </div>

                <div>
                  <label
                    style={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.8rem', display: 'block', marginBottom: '6px' }}
                  >
                    Token *
                  </label>
                  <input
                    type="text"
                    value={token}
                    onChange={(e) => handleTokenChange(e.target.value)}
                    onFocus={() => setFocused('token')}
                    onBlur={() => setFocused(null)}
                    style={{ ...inputStyle(focused === 'token'), fontFamily: 'monospace' }}
                  />
                  <FieldError msg={errors.token} />
                </div>

                <div>
                  <label
                    style={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.8rem', display: 'block', marginBottom: '6px' }}
                  >
                    Contraseña *
                  </label>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <input
                      type="text"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      onFocus={() => setFocused('password')}
                      onBlur={() => setFocused(null)}
                      style={{ ...inputStyle(focused === 'password'), fontFamily: 'monospace', flex: 1 }}
                    />
                    <button
                      type="button"
                      onClick={handleGeneratePassword}
                      style={{
                        backgroundColor: 'transparent',
                        border: '1px solid rgba(157,92,192,0.3)',
                        color: '#9D5CC0',
                        borderRadius: '8px',
                        padding: '10px 14px',
                        fontSize: '0.8rem',
                        cursor: 'pointer',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      Generar
                    </button>
                  </div>
                  <FieldError msg={errors.password} />
                </div>

                <div>
                  <label
                    style={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.8rem', display: 'block', marginBottom: '6px' }}
                  >
                    Notas internas
                  </label>
                  <textarea
                    value={notas}
                    onChange={(e) => setNotas(e.target.value)}
                    onFocus={() => setFocused('notas')}
                    onBlur={() => setFocused(null)}
                    rows={3}
                    style={{
                      ...inputStyle(focused === 'notas'),
                      resize: 'vertical',
                      fontFamily: 'inherit',
                    }}
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  style={{
                    width: '100%',
                    background: 'linear-gradient(135deg, #3B1E63, #9D5CC0)',
                    color: '#FFFFFF',
                    padding: '12px',
                    borderRadius: '8px',
                    fontSize: '0.875rem',
                    fontFamily: 'Merriweather, Georgia, serif',
                    fontWeight: 700,
                    border: 'none',
                    cursor: loading ? 'not-allowed' : 'pointer',
                    opacity: loading ? 0.7 : 1,
                    marginTop: '8px',
                  }}
                >
                  {loading ? 'Creando...' : 'Crear socio'}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>

      {modalData && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.75)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 50,
            padding: '16px',
          }}
        >
          <div
            style={{
              backgroundColor: '#1C0D35',
              border: '1px solid rgba(157,92,192,0.3)',
              borderRadius: '12px',
              padding: '36px',
              width: '100%',
              maxWidth: '480px',
            }}
          >
            <h2
              style={{
                fontFamily: 'Merriweather, Georgia, serif',
                color: '#FFFFFF',
                fontSize: '1.25rem',
                margin: '0 0 8px 0',
              }}
            >
              Socio creado exitosamente
            </h2>
            <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: '0.875rem', margin: '0 0 24px 0' }}>
              Guardá estos datos — la contraseña no se puede recuperar.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {[
                {
                  label: 'Link de acceso',
                  value: `${SITE_URL}/?token=${modalData.token}`,
                },
                { label: 'Email', value: modalData.email },
                { label: 'Contraseña', value: modalData.password },
              ].map(({ label, value }) => (
                <div key={label}>
                  <div
                    style={{
                      color: 'rgba(157,92,192,0.7)',
                      fontSize: '0.65rem',
                      textTransform: 'uppercase',
                      letterSpacing: '0.08em',
                      marginBottom: '4px',
                    }}
                  >
                    {label}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span
                      style={{
                        fontFamily: 'monospace',
                        fontSize: '0.8rem',
                        color: '#FFFFFF',
                        wordBreak: 'break-all',
                        flex: 1,
                      }}
                    >
                      {value}
                    </span>
                    <button
                      onClick={() => copyToClipboard(value)}
                      style={{
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        color: 'rgba(157,92,192,0.7)',
                        padding: '4px',
                        display: 'flex',
                        alignItems: 'center',
                        flexShrink: 0,
                      }}
                    >
                      <Copy size={14} />
                    </button>
                  </div>
                </div>
              ))}
            </div>

            <div style={{ display: 'flex', gap: '10px', marginTop: '28px' }}>
              <button
                onClick={copyAll}
                style={{
                  flex: 1,
                  backgroundColor: 'transparent',
                  border: '1px solid rgba(157,92,192,0.3)',
                  color: '#9D5CC0',
                  borderRadius: '8px',
                  padding: '10px',
                  fontSize: '0.875rem',
                  cursor: 'pointer',
                }}
              >
                Copiar todo
              </button>
              <button
                onClick={() => router.push('/admin/socios/' + modalData.socioId)}
                style={{
                  flex: 1,
                  background: 'linear-gradient(135deg, #3B1E63, #9D5CC0)',
                  border: 'none',
                  color: '#FFFFFF',
                  borderRadius: '8px',
                  padding: '10px',
                  fontSize: '0.875rem',
                  fontFamily: 'Merriweather, Georgia, serif',
                  fontWeight: 700,
                  cursor: 'pointer',
                }}
              >
                Ir al perfil
              </button>
            </div>
          </div>
        </div>
      )}

      <Toaster richColors />
    </>
  )
}
