import { createClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';

// Only allow same-site relative paths as the post-login destination.
// Anything else (absolute URL, protocol-relative //evil.com, backslash
// tricks) falls back to /dashboard, so a crafted ?next= link can never
// send a freshly signed-in user to another site.
function safeNext(value: string | null): string {
  if (!value) return '/dashboard';
  if (!value.startsWith('/')) return '/dashboard';
  if (value.startsWith('//') || value.startsWith('/\\')) return '/dashboard';
  if (value.includes('://')) return '/dashboard';
  return value;
}

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get('code');
  const next = safeNext(searchParams.get('next'));

  if (code) {
    const supabase = await createClient();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) {
      return NextResponse.redirect(`${origin}${next}`);
    }
  }

  return NextResponse.redirect(`${origin}/login?error=auth_failed`);
}
