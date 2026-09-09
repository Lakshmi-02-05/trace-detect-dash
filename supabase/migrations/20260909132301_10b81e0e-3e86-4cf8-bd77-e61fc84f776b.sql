CREATE TABLE public.uploads (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  filename text NOT NULL,
  total_lines integer NOT NULL DEFAULT 0,
  parsed_lines integer NOT NULL DEFAULT 0,
  malformed_lines integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.log_events (
  id bigserial PRIMARY KEY,
  upload_id uuid NOT NULL REFERENCES public.uploads(id) ON DELETE CASCADE,
  occurred_at timestamptz,
  username text,
  source_ip text,
  event_type text NOT NULL,
  status text NOT NULL,
  message text NOT NULL,
  line_number integer NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX log_events_upload_idx ON public.log_events(upload_id);
CREATE INDEX log_events_ip_idx ON public.log_events(source_ip);

CREATE TABLE public.incidents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  upload_id uuid NOT NULL REFERENCES public.uploads(id) ON DELETE CASCADE,
  rule_id text NOT NULL,
  alert_type text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  source_ip text,
  usernames text[] NOT NULL DEFAULT '{}',
  attempt_count integer NOT NULL DEFAULT 0,
  first_seen timestamptz,
  last_seen timestamptz,
  reason text NOT NULL,
  recommended_action text NOT NULL,
  evidence text[] NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW','INVESTIGATING','RESOLVED')),
  detected_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incidents_upload_idx ON public.incidents(upload_id);

GRANT SELECT, INSERT ON public.uploads TO anon, authenticated;
GRANT SELECT, INSERT ON public.log_events TO anon, authenticated;
GRANT USAGE, SELECT ON SEQUENCE public.log_events_id_seq TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.incidents TO anon, authenticated;
GRANT ALL ON public.uploads TO service_role;
GRANT ALL ON public.log_events TO service_role;
GRANT ALL ON public.incidents TO service_role;
GRANT ALL ON SEQUENCE public.log_events_id_seq TO service_role;

ALTER TABLE public.uploads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.log_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;

CREATE POLICY "uploads readable by everyone" ON public.uploads FOR SELECT TO anon, authenticated USING (true);
CREATE POLICY "uploads insertable by everyone" ON public.uploads FOR INSERT TO anon, authenticated WITH CHECK (true);

CREATE POLICY "log events readable by everyone" ON public.log_events FOR SELECT TO anon, authenticated USING (true);
CREATE POLICY "log events insertable by everyone" ON public.log_events FOR INSERT TO anon, authenticated WITH CHECK (true);

CREATE POLICY "incidents readable by everyone" ON public.incidents FOR SELECT TO anon, authenticated USING (true);
CREATE POLICY "incidents insertable by everyone" ON public.incidents FOR INSERT TO anon, authenticated WITH CHECK (true);
CREATE POLICY "incidents status updatable by everyone" ON public.incidents FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);