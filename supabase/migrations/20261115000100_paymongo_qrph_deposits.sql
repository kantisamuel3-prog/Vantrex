-- Vantrex PayMongo QRPH deposit integration
ALTER TABLE public.transactions
  ADD COLUMN IF NOT EXISTS payment_provider text,
  ADD COLUMN IF NOT EXISTS payment_order_id text,
  ADD COLUMN IF NOT EXISTS payment_intent_id text,
  ADD COLUMN IF NOT EXISTS payment_qr_url text;

CREATE UNIQUE INDEX IF NOT EXISTS transactions_payment_order_id_unique
  ON public.transactions(payment_order_id)
  WHERE payment_order_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS transactions_payment_intent_id_unique
  ON public.transactions(payment_intent_id)
  WHERE payment_intent_id IS NOT NULL;

CREATE OR REPLACE FUNCTION public.vantrex_confirm_paymongo_deposit(
  p_order_id text,
  p_payment_intent_id text,
  p_amount_cents bigint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_tx public.transactions%ROWTYPE;
BEGIN
  SELECT * INTO v_tx
  FROM public.transactions
  WHERE payment_order_id = p_order_id
    AND payment_intent_id = p_payment_intent_id
    AND payment_provider = 'paymongo'
    AND type = 'deposit'
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Vantrex deposit transaction not found';
  END IF;

  IF ROUND(v_tx.amount * 100)::bigint <> p_amount_cents THEN
    RAISE EXCEPTION 'Payment amount does not match transaction';
  END IF;

  -- Repeated PayMongo webhook deliveries must never credit twice.
  IF v_tx.status = 'completed' THEN
    RETURN false;
  END IF;
  IF v_tx.status <> 'pending' THEN
    RAISE EXCEPTION 'Transaction is not pending';
  END IF;

  UPDATE public.profiles
  SET balance = COALESCE(balance, 0) + v_tx.amount
  WHERE id = v_tx.user_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Vantrex profile not found';
  END IF;

  UPDATE public.transactions
  SET status = 'completed',
      description = 'PayMongo QRPH deposit confirmed'
  WHERE id = v_tx.id;

  RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION public.vantrex_confirm_paymongo_deposit(text, text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.vantrex_confirm_paymongo_deposit(text, text, bigint) TO service_role;
