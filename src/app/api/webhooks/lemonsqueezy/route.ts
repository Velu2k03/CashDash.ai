export const runtime = 'nodejs';
import { NextResponse } from 'next/server';
import crypto from 'node:crypto';

// LemonSqueezy webhook for CashDash subscriptions.
// TEST MODE ONLY. No live mode, no real payments.
// Fail-closed rules (Batch 1 security hardening):
// - No webhook secret configured -> reject everything, never verify with
//   an empty secret (an empty-secret HMAC is trivially forgeable).
// - No service-role key configured -> reject, never fall back to the anon
//   key (the anon key cannot bypass RLS, so updates would silently fail
//   or, worse, succeed under the wrong policy).
// - Live-mode events are ignored: this endpoint serves test mode only,
//   and the store is shared with Sortes, so live Sortes events must
//   never grant or change a CashDash tier.
// - Unknown variant ID -> acknowledge and ignore (HTTP 200), never grant
//   Pro as a fallback, and never return 400: LemonSqueezy retries 400s,
//   and every non-CashDash event from the shared store would retry.
// - Events without a CashDash user_id in custom_data (e.g. Sortes
//   events) -> acknowledge and ignore, same reason.
// - subscription_cancelled does NOT downgrade: in LemonSqueezy it means
//   paid until ends_at. Downgrade only on subscription_expired.
// - Only the CashDash Pro variant grants Pro (Free + Pro only decision).
//   Family/Business variants do not exist for CashDash and are ignored.
// Batch 5 (Stripe decision) will delete this route.
function isProVariant(variantId: string): boolean {
  return variantId === process.env.LEMONSQUEEZY_PRO_VARIANT_ID;
}

export async function POST(req: Request) {
  try {
    const secret = process.env.LEMONSQUEEZY_WEBHOOK_SECRET;
    if (!secret) {
      console.error('Webhook rejected: LEMONSQUEEZY_WEBHOOK_SECRET is not configured');
      return NextResponse.json({ error: 'Webhook secret not configured' }, { status: 500 });
    }

    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!supabaseUrl || !serviceRoleKey) {
      console.error('Webhook rejected: Supabase service-role key is not configured');
      return NextResponse.json({ error: 'Service-role key not configured' }, { status: 500 });
    }

    const rawBody = await req.text();
    const signature = req.headers.get('x-signature');

    if (!signature) {
      return NextResponse.json({ error: 'Missing signature' }, { status: 400 });
    }

    // Verify LemonSqueezy signature (HMAC SHA256 over the raw body)
    const digestHex = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
    if (
      signature.length !== digestHex.length ||
      !crypto.timingSafeEqual(Buffer.from(digestHex, 'utf8'), Buffer.from(signature, 'utf8'))
    ) {
      return NextResponse.json({ error: 'Invalid signature' }, { status: 400 });
    }

    const payload = JSON.parse(rawBody);
    const eventName = payload?.meta?.event_name;
    const obj = payload?.data?.attributes;
    if (!eventName || !obj) {
      return NextResponse.json({ error: 'Invalid payload' }, { status: 400 });
    }

    // Test mode only: ignore live events (e.g. Sortes live purchases in
    // the shared store). Acknowledge with 200 so they are not retried.
    if (obj.test_mode !== true) {
      console.log(`Webhook ignored: non-test event ${eventName}, test_mode=${obj.test_mode}`);
      return NextResponse.json({ success: true, ignored: 'not test mode' });
    }

    const userId = payload.meta.custom_data?.user_id;
    if (!userId) {
      console.log(`Webhook ignored: event ${eventName} has no CashDash user_id in custom_data`);
      return NextResponse.json({ success: true, ignored: 'no user_id' });
    }

    // Server-to-server call: use the service-role key so the update bypasses
    // RLS. The profiles trigger blocks tier changes by signed-in users only
    // (auth.uid() is NULL for service_role), so this update is allowed.
    const { createClient: createSupabaseClient } = await import('@supabase/supabase-js');
    const adminSupabase = createSupabaseClient(supabaseUrl, serviceRoleKey);

    if (eventName === 'subscription_created' || eventName === 'subscription_updated') {
      const status = obj.status;
      const variantId = obj.variant_id?.toString();
      if (!variantId) {
        return NextResponse.json({ error: 'Missing variant_id' }, { status: 400 });
      }

      // Only grant Pro for an active (or past-due / trial) Pro subscription.
      // Any other status (e.g. cancelled) leaves the tier untouched here:
      // the downgrade happens on subscription_expired, when paid access ends.
      if (status === 'active' || status === 'past_due' || status === 'on_trial') {
        if (!isProVariant(variantId)) {
          console.log(`Webhook ignored: unknown variant_id ${variantId} for ${eventName}`);
          return NextResponse.json({ success: true, ignored: 'unknown variant' });
        }

        const { error } = await adminSupabase
          .from('profiles')
          .update({
            subscription_tier: 'pro',
            lemonsqueezy_customer_id: obj.customer_id?.toString(),
            lemonsqueezy_subscription_id: payload.data.id?.toString(),
          })
          .eq('id', userId);

        if (error) throw error;
        console.log(`Updated user ${userId} to tier pro`);
      } else {
        console.log(`Webhook ignored: ${eventName} with status ${status}, tier unchanged`);
      }
    } else if (eventName === 'subscription_expired') {
      const variantId = obj.variant_id?.toString();
      if (variantId && !isProVariant(variantId)) {
        console.log(`Webhook ignored: subscription_expired for unknown variant_id ${variantId}`);
        return NextResponse.json({ success: true, ignored: 'unknown variant' });
      }

      const { error } = await adminSupabase
        .from('profiles')
        .update({ subscription_tier: 'free' })
        .eq('id', userId);

      if (error) throw error;
      console.log(`Downgraded user ${userId} to free (subscription expired)`);
    } else if (eventName === 'subscription_cancelled') {
      // Paid until ends_at: do not downgrade yet. The subscription_expired
      // event will downgrade when access actually ends.
      console.log(`Webhook noted: subscription_cancelled for user ${userId}, tier unchanged until expiry`);
    }
    // Other events (e.g. order_created for one-off orders) are acknowledged
    // and ignored: CashDash sells subscriptions only.

    return NextResponse.json({ success: true });
  } catch (err: any) {
    console.error('Webhook processing failed:', err.message);
    return NextResponse.json({ error: 'Webhook processing failed' }, { status: 500 });
  }
}
