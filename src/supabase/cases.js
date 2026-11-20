export async function registerLocalCase(supabase, caseNumber) {
  if (!supabase) {
    throw new Error('Team case registration requires a configured Supabase project.');
  }
  const normalized = typeof caseNumber === 'string' ? caseNumber.trim() : '';
  if (!normalized) {
    throw new Error('Open a local case before registering it for team access.');
  }

  const { data: existing, error: selectError } = await supabase
    .from('cases')
    .select('id')
    .eq('case_number', normalized)
    .maybeSingle();

  if (selectError) {
    throw new Error(selectError.message || 'Could not look up the case in team storage.');
  }
  if (existing?.id) {
    return existing.id;
  }

  const { data: created, error: insertError } = await supabase
    .from('cases')
    .insert({ case_number: normalized, title: normalized })
    .select('id')
    .single();

  if (insertError) {
    throw new Error(insertError.message || 'Could not register the case for team access.');
  }
  return created.id;
}

export async function getCaseMembershipRole(supabase, supabaseCaseId, userId) {
  if (!supabase || !supabaseCaseId || !userId) return null;

  const { data, error } = await supabase
    .from('case_members')
    .select('role')
    .eq('case_id', supabaseCaseId)
    .eq('user_id', userId)
    .maybeSingle();

  if (error) {
    throw new Error(error.message || 'Could not verify case membership role.');
  }
  return data?.role || null;
}
